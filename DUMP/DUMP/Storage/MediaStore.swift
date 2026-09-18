import Foundation

// MARK: - Media metadata

struct MediaInfo: Codable, Identifiable {

    let id: UUID
    let name: String
    let typeIdentifier: String
    let byteCount: UInt64
    let importedAt: Date
}


// MARK: - Encrypted media format

enum MediaFormat {

    static let magic =
        Data("DUMPv001".utf8)

    static let headerSize =
        4096

    static let chunkSize =
        1_048_576

    /// AES-GCM combined representation adds:
    ///
    /// 12-byte nonce
    /// 16-byte authentication tag
    static let overhead =
        28

    /// Defensive parser bound.
    static let maximumSize: UInt64 =
        1 << 40

    static func integer<T: FixedWidthInteger>(
        _ number: T
    ) -> Data {

        var bigEndian =
            number.bigEndian

        return withUnsafeBytes(
            of: &bigEndian
        ) {
            Data($0)
        }
    }

    static func uint32(
        _ data: Data
    ) throws -> UInt32 {

        guard data.count == 4 else {
            throw VaultError.damaged
        }

        return data.reduce(UInt32(0)) {
            ($0 << 8) | UInt32($1)
        }
    }

    /// Deterministic per-chunk nonce.
    ///
    /// This is safe ONLY because every media resource receives a
    /// completely new random 256-bit AES key.
    ///
    /// Therefore a nonce value is never intentionally reused under
    /// the same key.
    static func nonce(
        _ index: UInt64
    ) -> Data {

        Data(
            repeating: 0,
            count: 4
        ) + integer(index)
    }

    /// Domain-separated authenticated data for the encrypted header.
    static func headerAAD(
        _ id: UUID
    ) -> Data {

        magic +
        Data(id.uuidString.utf8)
    }

    /// Authenticated data binds every ciphertext chunk to:
    ///
    /// - this file
    /// - this chunk position
    /// - the expected plaintext size
    static func chunkAAD(
        _ id: UUID,
        index: UInt64,
        size: Int
    ) -> Data {

        headerAAD(id) +
        Data("/chunk/".utf8) +
        integer(index) +
        integer(UInt32(size))
    }
}


// MARK: - Vault media directory

struct MediaStore {

    let directory: URL

    init(
        directory: URL? = nil
    ) throws {

        if let directory {
            self.directory = directory
        } else {

            self.directory =
                try FileManager.default
                    .url(
                        for: .applicationSupportDirectory,
                        in: .userDomainMask,
                        appropriateFor: nil,
                        create: true
                    )
                    .appendingPathComponent(
                        "DUMP/Media",
                        isDirectory: true
                    )
        }

        try FileManager.default.createDirectory(
            at: self.directory,
            withIntermediateDirectories: true,
            attributes: [
                .protectionKey:
                    FileProtectionType.complete
            ]
        )

        try Self.protect(
            self.directory
        )

        /*
         Reapply protection to everything already inside the vault,
         including ciphertext left behind by an interrupted import.
        */

        let existing =
            try FileManager.default
                .contentsOfDirectory(
                    at: self.directory,
                    includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles]
                )

        for file in existing {
            try Self.protect(file)
        }
    }


    // MARK: Protection

    static func protect(
        _ url: URL
    ) throws {

        var target = url

        var values =
            URLResourceValues()

        /*
         Encrypted vault files are deliberately excluded from normal
         backup migration.

         Combined with Keychain's ThisDeviceOnly policy, this prevents
         producing a backup containing ciphertext whose credential
         record is intentionally device-bound.
        */

        values.isExcludedFromBackup = true

        try target.setResourceValues(
            values
        )

        /*
         NSFileProtectionComplete:

         file contents are inaccessible while the iPhone is locked.
        */

        try FileManager.default.setAttributes(
            [
                .protectionKey:
                    FileProtectionType.complete
            ],
            ofItemAtPath: target.path
        )

        let verification =
            try target.resourceValues(
                forKeys: [
                    .isExcludedFromBackupKey
                ]
            )

        guard verification.isExcludedFromBackup == true else {
            throw VaultError.storage
        }
    }


    // MARK: Paths

    func url(
        _ id: UUID
    ) -> URL {

        directory
            .appendingPathComponent(
                id.uuidString,
                isDirectory: false
            )
            .appendingPathExtension(
                "dump"
            )
    }


    // MARK: Existing media

    func containsFiles() throws -> Bool {

        let files =
            try FileManager.default
                .contentsOfDirectory(
                    at: directory,
                    includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles]
                )

        /*
         A partial encrypted import also counts as vault state.

         This deliberately prevents credential recreation/reset while
         interrupted encrypted data exists.
        */

        return files.contains {
            $0.pathExtension == "dump" ||
            $0.pathExtension == "partial"
        }
    }


    // MARK: List

    func list(
        master: SecretBytes,
        lease: SessionLease
    ) throws -> [MediaInfo] {

        try lease.check()

        let files =
            try FileManager.default
                .contentsOfDirectory(
                    at: directory,
                    includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles]
                )

        return try files
            .filter {
                $0.pathExtension == "dump"
            }
            .map { file in

                try lease.check()

                guard let id =
                        UUID(
                            uuidString:
                                file
                                    .deletingPathExtension()
                                    .lastPathComponent
                        )
                else {
                    throw VaultError.damaged
                }

                let reader =
                    try MediaReader(
                        url: file,
                        id: id,
                        master: master,
                        lease: lease
                    )

                defer {
                    reader.close()
                }

                return reader.info
            }
            .sorted {
                $0.importedAt >
                $1.importedAt
            }
    }


    // MARK: Remove

    func remove(
        _ id: UUID,
        lease: SessionLease
    ) throws {

        try lease.check()

        let target =
            url(id)

        guard FileManager.default
                .fileExists(
                    atPath: target.path
                )
        else {
            throw VaultError.unavailable
        }

        try lease.commit {

            try FileManager.default
                .removeItem(
                    at: target
                )
        }
    }
}


// MARK: - Encrypted streaming writer

/// Writes ciphertext only.
///
/// There are intentionally:
///
/// - no plaintext temporary files
/// - no plaintext cache files
/// - no whole-file plaintext buffers
/// - no decrypted filesystem staging locations
final class MediaWriter {

    let id =
        UUID()

    private let store:
        MediaStore

    private let master:
        SecretBytes

    /// Every media resource gets its own random AES-256 key.
    private let key:
        SecretBytes

    private let lease:
        SessionLease

    private let handle:
        FileHandle

    private let staging:
        URL

    /// At most one plaintext chunk is retained here.
    private var pending =
        Data()

    private var total:
        UInt64 = 0

    private var index:
        UInt64 = 0

    private var finished =
        false

    /*
     Once poisoned, the writer can never continue.

     This is important because retrying encryption after uncertain I/O
     could risk nonce/key misuse.
    */
    private var failed =
        false


    init(
        store: MediaStore,
        master: SecretBytes,
        lease: SessionLease
    ) throws {

        self.store =
            store

        self.master =
            master

        self.lease =
            lease

        try lease.check()

        /*
         Generate a fresh random AES-256 key for THIS media object.

         Chunk nonces may therefore safely begin from zero for every
         newly generated file.
        */

        key =
            try lease.own(
                AESBox.generateKey()
            )

        staging =
            store.directory
                .appendingPathComponent(
                    id.uuidString,
                    isDirectory: false
                )
                .appendingPathExtension(
                    "partial"
                )

        /*
         UUID collision is astronomically unlikely, but security code
         should still fail closed instead of overwriting.
        */

        guard !FileManager.default
                .fileExists(
                    atPath: staging.path
                ),
              !FileManager.default
                .fileExists(
                    atPath: store.url(id).path
                )
        else {

            key.destroy()

            throw VaultError.storage
        }

        guard FileManager.default
                .createFile(
                    atPath: staging.path,
                    contents: nil,
                    attributes: [
                        .protectionKey:
                            FileProtectionType.complete
                    ]
                )
        else {

            key.destroy()

            throw VaultError.storage
        }

        do {

            /*
             Exclude/protect the file BEFORE any meaningful vault data
             is written to it.
            */

            try MediaStore.protect(
                staging
            )

            handle =
                try FileHandle(
                    forUpdating: staging
                )

            /*
             Reserve the authenticated encrypted-header region.
            */

            try handle.write(
                contentsOf:
                    Data(
                        repeating: 0,
                        count: MediaFormat.headerSize
                    )
            )

        } catch {

            try? FileManager.default
                .removeItem(
                    at: staging
                )

            key.destroy()

            throw error
        }
    }


    // MARK: Append plaintext

    /// PhotoKit invokes its data/completion callbacks serially.
    ///
    /// Plaintext is accumulated only until one encryption chunk exists.
    func append(
        _ input: Data
    ) throws {

        try lease.check()

        guard !finished,
              !failed
        else {
            throw VaultError.damaged
        }

        var offset =
            input.startIndex

        while offset <
                input.endIndex {

            try lease.check()

            let available =
                MediaFormat.chunkSize -
                pending.count

            let remaining =
                input.endIndex -
                offset

            let count =
                min(
                    available,
                    remaining
                )

            pending.append(
                input[
                    offset ..<
                    offset + count
                ]
            )

            offset += count

            if pending.count ==
                MediaFormat.chunkSize {

                try flush()
            }
        }
    }


    // MARK: Encrypt chunk

    private func flush() throws {

        guard !failed else {
            throw VaultError.damaged
        }

        guard !pending.isEmpty else {
            return
        }

        /*
         Poison BEFORE sealing.

         If anything after this point fails, this writer cannot retry
         the same chunk/nonce.
        */

        failed = true

        defer {
            pending.wipe()
        }

        try lease.check()

        let pendingCount =
            UInt64(
                pending.count
            )

        guard pendingCount <=
                MediaFormat.maximumSize,
              total <=
                MediaFormat.maximumSize -
                pendingCount
        else {
            throw VaultError.storage
        }

        let aad =
            MediaFormat.chunkAAD(
                id,
                index: index,
                size: pending.count
            )

        /*
         nonce(index) is safe because `key` is freshly random for this
         media resource and index is strictly monotonically increasing.
        */

        let sealed =
            try AESBox.seal(
                pending,
                key: key,
                nonce:
                    MediaFormat.nonce(
                        index
                    ),
                aad: aad
            )

        guard sealed.count ==
                pending.count +
                MediaFormat.overhead
        else {
            throw VaultError.crypto
        }

        let start =
            try handle.offset()

        try handle.write(
            contentsOf: sealed
        )

        /*
         Read ciphertext back from disk and authenticate it.

         We verify what was actually written rather than trusting only
         the in-memory ciphertext buffer.
        */

        try handle.seek(
            toOffset: start
        )

        let readBack =
            try handle.read(
                upToCount:
                    sealed.count
            ) ?? Data()

        guard readBack.count ==
                sealed.count
        else {
            throw VaultError.storage
        }

        var plaintext =
            try AESBox.open(
                readBack,
                key: key,
                aad: aad
            )

        defer {
            plaintext.wipe()
        }

        guard SodiumRuntime.equal(
            plaintext,
            pending
        )
        else {
            throw VaultError.damaged
        }

        try lease.check()

        try handle.seek(
            toOffset:
                start +
                UInt64(
                    sealed.count
                )
        )

        total +=
            UInt64(
                pending.count
            )

        /*
         Prevent UInt64 rollover of the nonce counter.
        */

        guard index <
                UInt64.max
        else {
            throw VaultError.storage
        }

        index += 1

        /*
         Only now may another chunk be accepted.
        */

        failed = false
    }


    // MARK: Finish import

    func finish(
        name: String,
        typeIdentifier: String
    ) throws -> MediaInfo {

        guard !finished,
              !failed
        else {
            throw VaultError.damaged
        }

        try flush()

        /*
         Finalization is single-use.

         A failure after this point requires deleting the staging file,
         never attempting another finalization using this key/nonce set.
        */

        failed = true

        try lease.check()

        guard total > 0,
              !finished
        else {
            throw VaultError.damaged
        }

        /*
         Metadata itself is encrypted.

         Filename/type/date/size therefore aren't visible by examining
         the encrypted .dump file.
        */

        let safeName =
            String(
                name.prefix(256)
            )

        let safeType =
            String(
                typeIdentifier.prefix(256)
            )

        let info =
            MediaInfo(
                id: id,
                name: safeName,
                typeIdentifier: safeType,
                byteCount: total,
                importedAt: Date()
            )

        /*
         Header plaintext:

         [32-byte per-file AES key]
         [JSON metadata]

         The entire value is authenticated and encrypted with the
         random vault master key.
        */

        var rawKey =
            try key.copyData()

        defer {
            rawKey.wipe()
        }

        guard rawKey.count == 32 else {
            throw VaultError.crypto
        }

        var metadata =
            try JSONEncoder()
                .encode(info)

        defer {
            metadata.wipe()
        }

        rawKey.append(
            metadata
        )

        let encryptedHeader =
            try AESBox.seal(
                rawKey,
                key: master,
                aad:
                    MediaFormat.headerAAD(
                        id
                    )
            )

        /*
         Header structure:

         magic             8 bytes
         encrypted length  4 bytes
         AES-GCM box
         zero padding
        */

        guard encryptedHeader.count >=
                MediaFormat.overhead,
              encryptedHeader.count + 12 <=
                MediaFormat.headerSize,
              encryptedHeader.count <=
                Int(UInt32.max)
        else {
            throw VaultError.damaged
        }

        var header =
            MediaFormat.magic +
            MediaFormat.integer(
                UInt32(
                    encryptedHeader.count
                )
            ) +
            encryptedHeader

        header.append(
            Data(
                repeating: 0,
                count:
                    MediaFormat.headerSize -
                    header.count
            )
        )

        try lease.check()

        try handle.seek(
            toOffset: 0
        )

        try handle.write(
            contentsOf: header
        )

        /*
         Force encrypted contents toward stable storage before
         verification and rename.
        */

        try handle.synchronize()

        try handle.close()

        /*
         Re-open the staging file through the SAME reader used by the
         application and authenticate every encrypted chunk.

         Only a completely readable/authenticated file may enter the
         final vault namespace.
        */

        let reader =
            try MediaReader(
                url: staging,
                id: id,
                master: master,
                lease: lease
            )

        defer {
            reader.close()
        }

        try reader.verifyAll()

        try lease.check()

        let finalURL =
            store.url(id)

        guard !FileManager.default
                .fileExists(
                    atPath: finalURL.path
                )
        else {
            throw VaultError.storage
        }

        try lease.commit {

            try FileManager.default
                .moveItem(
                    at: staging,
                    to: finalURL
                )

            do {

                try MediaStore.protect(
                    finalURL
                )

            } catch {

                /*
                 Fail closed.

                 A final vault object that cannot receive the required
                 protection policy is removed rather than retained.
                */

                try? FileManager.default
                    .removeItem(
                        at: finalURL
                    )

                throw error
            }
        }

        finished = true

        key.destroy()

        return info
    }


    // MARK: Cleanup

    deinit {

        pending.wipe()

        key.destroy()

        try? handle.close()

        /*
         Interrupted imports contain ciphertext only and are removed
         when their writer dies.
        */

        if !finished {

            try? FileManager.default
                .removeItem(
                    at: staging
                )
        }
    }
}


// MARK: - Encrypted streaming reader

final class MediaReader:
    @unchecked Sendable {

    let info:
        MediaInfo

    private let key:
        SecretBytes

    private let lease:
        SessionLease

    private let handle:
        FileHandle

    private let lock =
        NSRecursiveLock()

    private var closed =
        false


    init(
        url: URL,
        id: UUID,
        master: SecretBytes,
        lease: SessionLease
    ) throws {

        self.lease =
            lease

        try lease.check()

        /*
         Reject unexpected paths before opening.

         The caller's UUID must correspond exactly to the encrypted
         object's filename.
        */

        guard url.pathExtension ==
                "dump" ||
              url.pathExtension ==
                "partial"
        else {
            throw VaultError.damaged
        }

        let file =
            try FileHandle(
                forReadingFrom: url
            )

        do {

            let header =
                try file.read(
                    upToCount:
                        MediaFormat.headerSize
                ) ?? Data()

            guard header.count ==
                    MediaFormat.headerSize,
                  header.prefix(
                    MediaFormat.magic.count
                  ) ==
                    MediaFormat.magic
            else {
                throw VaultError.damaged
            }

            let encryptedHeaderSize =
                Int(
                    try MediaFormat.uint32(
                        header.subdata(
                            in: 8..<12
                        )
                    )
                )

            /*
             Minimum encrypted header contains at least:
             32-byte file key + AES-GCM overhead.
            */

            guard encryptedHeaderSize >=
                    32 +
                    MediaFormat.overhead,
                  encryptedHeaderSize <=
                    MediaFormat.headerSize -
                    12
            else {
                throw VaultError.damaged
            }

            var plaintextHeader: Data

            do {

                plaintextHeader =
                    try AESBox.open(
                        header.subdata(
                            in:
                                12 ..<
                                12 +
                                encryptedHeaderSize
                        ),
                        key: master,
                        aad:
                            MediaFormat.headerAAD(
                                id
                            )
                    )

            } catch {

                throw VaultError.damaged
            }

            defer {
                plaintextHeader.wipe()
            }

            guard plaintextHeader.count >
                    32
            else {
                throw VaultError.damaged
            }

            /*
             Parse encrypted metadata.
            */

            let metadataData =
                plaintextHeader.subdata(
                    in:
                        32 ..<
                        plaintextHeader.count
                )

            let metadata: MediaInfo

            do {

                metadata =
                    try JSONDecoder()
                        .decode(
                            MediaInfo.self,
                            from:
                                metadataData
                        )

            } catch {

                throw VaultError.damaged
            }

            guard metadata.id ==
                    id,
                  metadata.byteCount >
                    0,
                  metadata.byteCount <=
                    MediaFormat.maximumSize,
                  metadata.name.count <=
                    256,
                  metadata.typeIdentifier.count <=
                    256
            else {
                throw VaultError.damaged
            }

            /*
             Compute the ONLY valid ciphertext length for the declared
             plaintext length.

             Appended/truncated/reordered data therefore fails.
            */

            let chunks =
                (
                    metadata.byteCount +
                    UInt64(
                        MediaFormat.chunkSize
                    ) -
                    1
                ) /
                UInt64(
                    MediaFormat.chunkSize
                )

            guard chunks > 0 else {
                throw VaultError.damaged
            }

            let overheadBytes =
                chunks *
                UInt64(
                    MediaFormat.overhead
                )

            guard metadata.byteCount <=
                    UInt64.max -
                    UInt64(
                        MediaFormat.headerSize
                    ),
                  metadata.byteCount +
                    UInt64(
                        MediaFormat.headerSize
                    ) <=
                    UInt64.max -
                    overheadBytes
            else {
                throw VaultError.damaged
            }

            let expectedSize =
                UInt64(
                    MediaFormat.headerSize
                ) +
                metadata.byteCount +
                overheadBytes

            let actualSize =
                try file.seekToEnd()

            guard actualSize ==
                    expectedSize
            else {
                throw VaultError.damaged
            }

            /*
             Extract the random per-media AES key only after the
             authenticated header has been successfully opened.
            */

            var rawKey =
                plaintextHeader.subdata(
                    in: 0..<32
                )

            defer {
                rawKey.wipe()
            }

            key =
                try lease.own(
                    SecretBytes(
                        rawKey
                    )
                )

            info =
                metadata

            handle =
                file

        } catch {

            try? file.close()

            throw error
        }
    }


    // MARK: Decrypt chunk

    private func chunk(
        _ index: UInt64
    ) throws -> Data {

        try lease.check()

        guard !closed else {
            throw VaultError.locked
        }

        /*
         Prevent multiplication overflow before calculating offsets.
        */

        let chunkSize =
            UInt64(
                MediaFormat.chunkSize
            )

        guard index <=
                UInt64.max /
                chunkSize
        else {
            throw VaultError.damaged
        }

        let plaintextStart =
            index *
            chunkSize

        guard plaintextStart <
                info.byteCount
        else {
            throw VaultError.damaged
        }

        let plaintextLength =
            Int(
                min(
                    chunkSize,
                    info.byteCount -
                    plaintextStart
                )
            )

        let storedChunkSize =
            UInt64(
                MediaFormat.chunkSize +
                MediaFormat.overhead
            )

        guard index <=
                (
                    UInt64.max -
                    UInt64(
                        MediaFormat.headerSize
                    )
                ) /
                storedChunkSize
        else {
            throw VaultError.damaged
        }

        let fileOffset =
            UInt64(
                MediaFormat.headerSize
            ) +
            index *
            storedChunkSize

        try handle.seek(
            toOffset:
                fileOffset
        )

        let ciphertext =
            try handle.read(
                upToCount:
                    plaintextLength +
                    MediaFormat.overhead
            ) ?? Data()

        guard ciphertext.count ==
                plaintextLength +
                MediaFormat.overhead
        else {
            throw VaultError.damaged
        }

        /*
         CryptoKit combined AES-GCM representation starts with the
         12-byte nonce.

         Verify it matches the nonce dictated by this chunk index.
        */

        guard ciphertext.prefix(12) ==
                MediaFormat.nonce(
                    index
                )
        else {
            throw VaultError.damaged
        }

        var plaintext: Data

        do {

            plaintext =
                try AESBox.open(
                    ciphertext,
                    key: key,
                    aad:
                        MediaFormat.chunkAAD(
                            info.id,
                            index: index,
                            size:
                                plaintextLength
                        )
                )

        } catch {

            throw VaultError.damaged
        }

        guard plaintext.count ==
                plaintextLength
        else {

            plaintext.wipe()

            throw VaultError.damaged
        }

        do {

            try lease.check()

            return plaintext

        } catch {

            plaintext.wipe()

            throw error
        }
    }


    // MARK: Bounded read

    /// Every returned plaintext application buffer is bounded to 1 MiB.
    func read(
        offset: UInt64,
        count: Int
    ) throws -> Data {

        lock.lock()
        defer {
            lock.unlock()
        }

        try lease.check()

        guard !closed,
              offset <=
                info.byteCount,
              count >= 0,
              count <=
                MediaFormat.chunkSize
        else {
            throw VaultError.damaged
        }

        let wanted =
            Int(
                min(
                    UInt64(count),
                    info.byteCount -
                    offset
                )
            )

        if wanted == 0 {
            return Data()
        }

        var output =
            Data()

        /*
         Avoid unnecessary reallocations of sensitive plaintext.
        */

        output.reserveCapacity(
            wanted
        )

        do {

            while output.count <
                    wanted {

                try lease.check()

                let position =
                    offset +
                    UInt64(
                        output.count
                    )

                let chunkIndex =
                    position /
                    UInt64(
                        MediaFormat.chunkSize
                    )

                let withinChunk =
                    Int(
                        position %
                        UInt64(
                            MediaFormat.chunkSize
                        )
                    )

                var plaintext =
                    try chunk(
                        chunkIndex
                    )

                defer {
                    plaintext.wipe()
                }

                guard withinChunk <=
                        plaintext.count
                else {
                    throw VaultError.damaged
                }

                let available =
                    plaintext.count -
                    withinChunk

                let remaining =
                    wanted -
                    output.count

                let take =
                    min(
                        remaining,
                        available
                    )

                guard take > 0 else {
                    throw VaultError.damaged
                }

                output.append(
                    plaintext[
                        withinChunk ..<
                        withinChunk +
                        take
                    ]
                )
            }

            try lease.check()

            return output

        } catch {

            output.wipe()

            throw error
        }
    }


    // MARK: Full integrity verification

    func verifyAll() throws {

        lock.lock()
        defer {
            lock.unlock()
        }

        try lease.check()

        var chunkIndex:
            UInt64 = 0

        let chunkSize =
            UInt64(
                MediaFormat.chunkSize
            )

        while chunkIndex *
                chunkSize <
                info.byteCount {

            try lease.check()

            var plaintext =
                try chunk(
                    chunkIndex
                )

            plaintext.wipe()

            guard chunkIndex <
                    UInt64.max
            else {
                throw VaultError.damaged
            }

            chunkIndex += 1
        }

        try lease.check()
    }


    // MARK: Close

    func close() {

        lock.lock()
        defer {
            lock.unlock()
        }

        guard !closed else {
            return
        }

        closed = true

        key.destroy()

        try? handle.close()
    }


    deinit {
        close()
    }
}
