import Foundation
import Photos
import UniformTypeIdentifiers
import Darwin

struct ExportOutcome {
    var exported: Bool
    var cleanup: TemporaryExport.Cleanup
}


// MARK: - Temporary plaintext export

/// The ONLY intentional exception to DUMP's no-plaintext-files rule.
///
/// IMPORTANT:
///
/// This class minimizes the lifetime and accessibility of plaintext,
/// but cannot guarantee physical secure erasure on APFS / flash storage.
///
/// Exporting also necessarily gives Photos an unencrypted copy.
final class TemporaryExport {

    enum Cleanup: Equatable {
        case removed
        case removedWithoutOverwrite
        case removalFailed
    }

    let url: URL

    private let handle: FileHandle
    private var cleaned = false


    init(extension suffix: String) throws {

        /*
         Accept only a simple ASCII extension.

         No slashes, dots, Unicode path tricks, or arbitrary filenames
         are accepted here.
        */

        let safeSuffix: String

        if !suffix.isEmpty,
           suffix.count <= 16,
           suffix.allSatisfy({
               $0.isASCII &&
               ($0.isLetter || $0.isNumber)
           }) {

            safeSuffix = suffix.lowercased()

        } else {

            safeSuffix = "bin"
        }

        let temporaryDirectory =
            URL(
                fileURLWithPath:
                    NSTemporaryDirectory(),
                isDirectory: true
            )

        url =
            temporaryDirectory
                .appendingPathComponent(
                    "DUMP-export-" +
                    UUID().uuidString,
                    isDirectory: false
                )
                .appendingPathExtension(
                    safeSuffix
                )

        /*
         Security-sensitive creation:

         O_CREAT   create the file
         O_EXCL    fail if it already exists
         O_RDWR    read/write descriptor
         O_NOFOLLOW reject a symlink at the final path

         0600:
         owner read/write only
        */

        let descriptor =
            Darwin.open(
                url.path,
                O_CREAT |
                O_EXCL |
                O_RDWR |
                O_NOFOLLOW,
                mode_t(0o600)
            )

        guard descriptor >= 0 else {
            throw VaultError.storage
        }

        handle =
            FileHandle(
                fileDescriptor: descriptor,
                closeOnDealloc: true
            )

        do {

            /*
             At this moment the file is still EMPTY.

             Apply protection before writing any plaintext.
            */

            try MediaStore.protect(
                url
            )

            try FileManager.default
                .setAttributes(
                    [
                        .posixPermissions:
                            NSNumber(value: 0o600)
                    ],
                    ofItemAtPath:
                        url.path
                )

            /*
             Verify permissions instead of merely assuming the
             attribute operation succeeded.
            */

            let attributes =
                try FileManager.default
                    .attributesOfItem(
                        atPath: url.path
                    )

            if let permissions =
                attributes[.posixPermissions]
                    as? NSNumber {

                guard permissions.intValue & 0o077 == 0 else {
                    throw VaultError.storage
                }

            } else {

                throw VaultError.storage
            }

        } catch {

            try? handle.close()

            try? FileManager.default
                .removeItem(
                    at: url
                )

            throw error
        }
    }


    // MARK: Write decrypted media

    func write(
        reader: MediaReader,
        lease: SessionLease
    ) throws {

        try lease.check()

        var offset: UInt64 = 0

        while offset <
                reader.info.byteCount {

            try lease.check()

            try Task.checkCancellation()

            let remaining =
                reader.info.byteCount -
                offset

            let requested =
                Int(
                    min(
                        UInt64(
                            MediaFormat.chunkSize
                        ),
                        remaining
                    )
                )

            guard requested > 0 else {
                throw VaultError.damaged
            }

            /*
             At most one MediaFormat.chunkSize plaintext buffer exists
             here at a time.
            */

            var plaintext =
                try reader.read(
                    offset: offset,
                    count: requested
                )

            defer {
                plaintext.wipe()
            }

            guard !plaintext.isEmpty,
                  plaintext.count <= requested
            else {
                throw VaultError.damaged
            }

            try lease.check()

            try handle.write(
                contentsOf: plaintext
            )

            offset +=
                UInt64(
                    plaintext.count
                )
        }

        guard offset ==
                reader.info.byteCount
        else {
            throw VaultError.damaged
        }

        /*
         Flush the temporary plaintext file before handing it to
         Photos.
        */

        try handle.synchronize()

        try lease.check()
    }


    // MARK: Cleanup

    /// Attempts:
    ///
    /// 1. logical overwrite
    /// 2. synchronize
    /// 3. close
    /// 4. unlink
    ///
    /// The unlink is attempted EVEN if overwrite fails.
    ///
    /// The overwrite is defense-in-depth only.
    ///
    /// APFS, SSD wear leveling and copy-on-write behavior mean this
    /// MUST NOT be described as guaranteed physical secure erasure.
    @discardableResult
    func cleanup() -> Cleanup {

        if cleaned {
            return .removed
        }

        cleaned = true

        var overwriteSucceeded =
            true

        do {

            let length =
                try handle.seekToEnd()

            try handle.seek(
                toOffset: 0
            )

            /*
             Small fixed zero buffer rather than allocating a second
             buffer the size of the exported media.
            */

            let zeros =
                Data(
                    repeating: 0,
                    count: 65_536
                )

            var offset: UInt64 = 0

            while offset < length {

                let remaining =
                    length -
                    offset

                let count =
                    Int(
                        min(
                            UInt64(
                                zeros.count
                            ),
                            remaining
                        )
                    )

                try handle.write(
                    contentsOf:
                        zeros.prefix(
                            count
                        )
                )

                offset +=
                    UInt64(
                        count
                    )
            }

            try handle.synchronize()

        } catch {

            /*
             Still unlink below.

             Failure to overwrite must NEVER prevent deletion.
            */

            overwriteSucceeded =
                false
        }

        try? handle.close()

        do {

            if FileManager.default
                .fileExists(
                    atPath: url.path
                ) {

                try FileManager.default
                    .removeItem(
                        at: url
                    )
            }

        } catch {

            return .removalFailed
        }

        return overwriteSucceeded
            ? .removed
            : .removedWithoutOverwrite
    }


    deinit {

        /*
         Covers normal Swift unwinding.

         This cannot run after every possible process termination,
         device crash or power loss.
        */

        if !cleaned {
            cleanup()
        }
    }
}


// MARK: - Photos export

enum PhotosExporter {

    static func run(
        item: MediaInfo,
        store: MediaStore,
        master: SecretBytes,
        lease: SessionLease
    ) async throws -> ExportOutcome {

        try lease.check()

        /*
         Only images and movies are exportable through Photos.
        */

        guard let type =
                UTType(
                    item.typeIdentifier
                ),
              type.conforms(
                to: .image
              ) ||
              type.conforms(
                to: .movie
              )
        else {
            throw VaultError.unavailable
        }

        /*
         Derive the temporary extension from UTType rather than from
         the encrypted user-visible filename.
        */

        let suffix =
            type.preferredFilenameExtension ??
            "bin"

        return await perform(
            item: item,
            store: store,
            master: master,
            lease: lease,
            suffix: suffix
        ) { url in

            try lease.check()

            try Task.checkCancellation()

            let state =
                ExportCommitState()

            try await PHPhotoLibrary
                .shared()
                .performChanges {

                    /*
                     This closure itself isn't async.

                     lease.commit() guarantees the lease is still alive
                     while the Photos creation request is constructed.
                    */

                    do {

                        try lease.commit {

                            let request =
                                PHAssetCreationRequest
                                    .forAsset()

                            let options =
                                PHAssetResourceCreationOptions()

                            /*
                             Photos must COPY the file.

                             DUMP retains ownership of its temporary
                             plaintext so DUMP can immediately clean it
                             after Photos finishes its transaction.
                            */

                            options.shouldMoveFile =
                                false

                            options.uniformTypeIdentifier =
                                item.typeIdentifier

                            /*
                             Metadata supplied to Photos is necessarily
                             outside DUMP's encrypted vault after export.
                            */

                            options.originalFilename =
                                String(
                                    item.name.prefix(
                                        256
                                    )
                                )

                            let resourceType:
                                PHAssetResourceType =
                                    type.conforms(
                                        to: .movie
                                    )
                                    ? .video
                                    : .photo

                            request.addResource(
                                with: resourceType,
                                fileURL: url,
                                options: options
                            )

                            state.markCommitted()
                        }

                    } catch {

                        /*
                         If the lease was revoked, no new Photos
                         resource request is intentionally constructed.
                        */
                    }
                }

            try Task.checkCancellation()

            return state.didCommit
        }
    }


    // MARK: Injectable export implementation

    /// The injectable handoff allows cleanup behavior to be tested
    /// without writing into a user's Photos library.
    static func perform(
        item: MediaInfo,
        store: MediaStore,
        master: SecretBytes,
        lease: SessionLease,
        suffix: String,
        handoff: (URL) async throws -> Bool
    ) async -> ExportOutcome {

        var result =
            ExportOutcome(
                exported: false,
                cleanup: .removed
            )

        /*
         This scope guarantees cleanup during normal Swift unwinding
         regardless of whether decryption, handoff, or Photos fails.
        */

        do {

            try lease.check()

            try Task.checkCancellation()

            let temporary =
                try TemporaryExport(
                    extension: suffix
                )

            defer {

                result.cleanup =
                    temporary.cleanup()
            }

            /*
             Reader validates/authenticates the encrypted header before
             releasing the per-resource AES key.
            */

            let reader =
                try MediaReader(
                    url:
                        store.url(
                            item.id
                        ),
                    id:
                        item.id,
                    master:
                        master,
                    lease:
                        lease
                )

            defer {
                reader.close()
            }

            /*
             Decrypt directly from encrypted storage into the protected
             temporary export file in bounded chunks.
            */

            try temporary.write(
                reader: reader,
                lease: lease
            )

            /*
             Destroy the media resource key before plaintext is handed
             to Photos.

             The temporary plaintext file remains protected by iOS file
             protection until cleanup.
            */

            reader.close()

            try lease.check()

            try Task.checkCancellation()

            result.exported =
                try await handoff(
                    temporary.url
                )

        } catch {

            /*
             The defer above cleans the temporary file before this
             function returns from its scope.

             No plaintext paths or media contents are logged.
            */

            result.exported =
                false
        }

        return result
    }
}


// MARK: - Photos transaction state

private final class ExportCommitState:
    @unchecked Sendable {

    private let lock =
        NSLock()

    private var committed =
        false

    func markCommitted() {

        lock.withLock {
            committed = true
        }
    }

    var didCommit: Bool {

        lock.withLock {
            committed
        }
    }
}
