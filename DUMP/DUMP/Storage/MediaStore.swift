import Foundation

struct MediaInfo: Codable, Identifiable {
    let id: UUID
    let name: String
    let typeIdentifier: String
    let byteCount: UInt64
    let importedAt: Date
}

enum MediaFormat {
    static let magic = Data("DUMPv001".utf8)
    static let headerSize = 4096
    static let chunkSize = 1_048_576
    static let overhead = 28 // 96-bit nonce + 128-bit authentication tag.
    static let maximumSize: UInt64 = 1 << 40 // Parser bound: 1 TiB/resource.
    static func integer<T: FixedWidthInteger>(_ n: T) -> Data {
        var big = n.bigEndian
        return withUnsafeBytes(of: &big) { Data($0) }
    }
    static func uint32(_ data: Data) throws -> UInt32 {
        guard data.count == 4 else { throw VaultError.damaged }
        return data.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
    static func nonce(_ index: UInt64) -> Data { Data(repeating: 0, count: 4) + integer(index) }
    static func headerAAD(_ id: UUID) -> Data { magic + Data(id.uuidString.utf8) }
    static func chunkAAD(_ id: UUID, index: UInt64, size: Int) -> Data {
        headerAAD(id) + Data("/chunk/".utf8) + integer(index) + integer(UInt32(size))
    }
}

struct MediaStore {
    let directory: URL
    init(directory: URL? = nil) throws {
        self.directory = try directory ?? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("DUMP/Media", isDirectory: true)
        try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true,
                                               attributes: [.protectionKey: FileProtectionType.complete])
        try Self.protect(self.directory)
        // Reapply and verify every file, including interrupted ciphertext imports.
        for url in try FileManager.default.contentsOfDirectory(at: self.directory, includingPropertiesForKeys: nil) {
            try Self.protect(url)
        }
    }
    static func protect(_ url: URL) throws {
        var target = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try target.setResourceValues(values)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: target.path)
        guard try target.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else { throw VaultError.storage }
    }
    func url(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString).appendingPathExtension("dump") }
    func containsFiles() throws -> Bool {
        try !FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).isEmpty
    }
    func list(master: SecretBytes, lease: SessionLease) throws -> [MediaInfo] {
        try lease.check()
        return try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "dump" }
            .map { file in
                guard let id = UUID(uuidString: file.deletingPathExtension().lastPathComponent) else { throw VaultError.damaged }
                let reader = try MediaReader(url: file, id: id, master: master, lease: lease)
                defer { reader.close() }
                return reader.info
            }.sorted { $0.importedAt > $1.importedAt }
    }
    func remove(_ id: UUID, lease: SessionLease) throws {
        try lease.commit { try FileManager.default.removeItem(at: url(id)) }
    }
}

/// Writes ciphertext only. No plaintext paths, caches, whole-file Data or temp files.
final class MediaWriter {
    let id = UUID()
    private let store: MediaStore
    private let master: SecretBytes
    private let key: SecretBytes
    private let lease: SessionLease
    private let handle: FileHandle
    private let staging: URL
    private var pending = Data()
    private var total: UInt64 = 0
    private var index: UInt64 = 0
    private var finished = false
    private var failed = false
    init(store: MediaStore, master: SecretBytes, lease: SessionLease) throws {
        self.store = store; self.master = master; self.lease = lease
        try lease.check()
        key = try lease.own(AESBox.generateKey())
        staging = store.directory.appendingPathComponent(id.uuidString).appendingPathExtension("partial")
        guard FileManager.default.createFile(atPath: staging.path, contents: nil,
                                            attributes: [.protectionKey: FileProtectionType.complete]) else { throw VaultError.storage }
        do {
            try MediaStore.protect(staging) // Set exclusion before writing ANY bytes.
            handle = try FileHandle(forUpdating: staging)
            try handle.write(contentsOf: Data(repeating: 0, count: MediaFormat.headerSize))
        } catch {
            try? FileManager.default.removeItem(at: staging)
            key.destroy()
            throw error
        }
    }
    /// PhotoKit invokes its data/completion callbacks on one serial queue.
    func append(_ input: Data) throws {
        try lease.check()
        guard !finished, !failed else { throw VaultError.damaged }
        var offset = input.startIndex
        while offset < input.endIndex {
            try lease.check()
            let count = min(MediaFormat.chunkSize - pending.count, input.endIndex - offset)
            pending.append(input[offset ..< offset + count])
            offset += count
            if pending.count == MediaFormat.chunkSize { try flush() }
        }
    }
    private func flush() throws {
        guard !failed else { throw VaultError.damaged }
        guard !pending.isEmpty else { return }
        failed = true // Poison the writer before sealing: an I/O failure must never retry a nonce.
        defer { pending.wipe() }
        try lease.check()
        guard total + UInt64(pending.count) <= MediaFormat.maximumSize else { throw VaultError.storage }
        let aad = MediaFormat.chunkAAD(id, index: index, size: pending.count)
        let sealed = try AESBox.seal(pending, key: key, nonce: MediaFormat.nonce(index), aad: aad)
        let start = try handle.offset()
        try handle.write(contentsOf: sealed)
        // Verify bytes read back from the destination, not merely the in-memory seal result.
        try handle.seek(toOffset: start)
        let readBack = try handle.read(upToCount: sealed.count) ?? Data()
        var plain = try AESBox.open(readBack, key: key, aad: aad)
        defer { plain.wipe() }
        guard SodiumRuntime.equal(plain, pending) else { throw VaultError.damaged }
        try handle.seek(toOffset: start + UInt64(sealed.count))
        total += UInt64(pending.count)
        index += 1
        failed = false
    }
    func finish(name: String, typeIdentifier: String) throws -> MediaInfo {
        guard !finished, !failed else { throw VaultError.damaged }
        try flush()
        failed = true // Finalization is single-use, even if header/rename/verification fails.
        try lease.check()
        guard total > 0, !finished else { throw VaultError.damaged }
        let info = MediaInfo(id: id, name: String(name.prefix(256)), typeIdentifier: typeIdentifier, byteCount: total, importedAt: Date())
        var raw = try key.copyData()
        defer { raw.wipe() }
        var description = try JSONEncoder().encode(info)
        defer { description.wipe() }
        raw.append(description)
        let box = try AESBox.seal(raw, key: master, aad: MediaFormat.headerAAD(id))
        guard box.count + 12 <= MediaFormat.headerSize else { throw VaultError.damaged }
        var header = MediaFormat.magic + MediaFormat.integer(UInt32(box.count)) + box
        header.append(Data(repeating: 0, count: MediaFormat.headerSize - header.count))
        try handle.seek(toOffset: 0)
        try handle.write(contentsOf: header)
        try handle.synchronize()
        try handle.close()
        let reader = try MediaReader(url: staging, id: id, master: master, lease: lease)
        defer { reader.close() }
        try reader.verifyAll()
        try lease.commit {
            try FileManager.default.moveItem(at: staging, to: store.url(id))
            do { try MediaStore.protect(store.url(id)) }
            catch { try? FileManager.default.removeItem(at: store.url(id)); throw error }
        }
        finished = true
        key.destroy()
        return info
    }
    deinit {
        pending.wipe(); key.destroy()
        try? handle.close()
        if !finished { try? FileManager.default.removeItem(at: staging) }
    }
}

final class MediaReader: @unchecked Sendable {
    let info: MediaInfo
    private let key: SecretBytes
    private let lease: SessionLease
    private let handle: FileHandle
    private let lock = NSRecursiveLock()
    private var closed = false
    init(url: URL, id: UUID, master: SecretBytes, lease: SessionLease) throws {
        self.lease = lease
        try lease.check()
        let file = try FileHandle(forReadingFrom: url)
        do {
            let header = try file.read(upToCount: MediaFormat.headerSize) ?? Data()
            guard header.count == MediaFormat.headerSize, header.prefix(8) == MediaFormat.magic else { throw VaultError.damaged }
            let count = Int(try MediaFormat.uint32(header.subdata(in: 8..<12)))
            guard count >= 60, count <= MediaFormat.headerSize - 12 else { throw VaultError.damaged }
            var plain = try AESBox.open(header.subdata(in: 12..<12 + count), key: master, aad: MediaFormat.headerAAD(id))
            defer { plain.wipe() }
            guard plain.count > 32 else { throw VaultError.damaged }
            let meta = try JSONDecoder().decode(MediaInfo.self, from: plain.subdata(in: 32..<plain.count))
            guard meta.id == id, meta.byteCount > 0, meta.byteCount <= MediaFormat.maximumSize else { throw VaultError.damaged }
            let chunks = (meta.byteCount + UInt64(MediaFormat.chunkSize) - 1) / UInt64(MediaFormat.chunkSize)
            let expected = UInt64(MediaFormat.headerSize) + meta.byteCount + chunks * UInt64(MediaFormat.overhead)
            guard try file.seekToEnd() == expected else { throw VaultError.damaged }
            var rawKey = plain.subdata(in: 0..<32)
            defer { rawKey.wipe() }
            key = try lease.own(SecretBytes(rawKey))
            info = meta
            handle = file
        } catch { try? file.close(); throw error }
    }
    private func chunk(_ index: UInt64) throws -> Data {
        try lease.check()
        guard !closed else { throw VaultError.locked }
        let start = index * UInt64(MediaFormat.chunkSize)
        guard start < info.byteCount else { throw VaultError.damaged }
        let length = Int(min(UInt64(MediaFormat.chunkSize), info.byteCount - start))
        let offset = UInt64(MediaFormat.headerSize) + index * UInt64(MediaFormat.chunkSize + MediaFormat.overhead)
        try handle.seek(toOffset: offset)
        let box = try handle.read(upToCount: length + MediaFormat.overhead) ?? Data()
        guard box.count == length + MediaFormat.overhead, box.prefix(12) == MediaFormat.nonce(index) else { throw VaultError.damaged }
        var result = try AESBox.open(box, key: key, aad: MediaFormat.chunkAAD(info.id, index: index, size: length))
        do { try lease.check(); return result }
        catch { result.wipe(); throw error }
    }
    /// Every returned application buffer is bounded to one MiB.
    func read(offset: UInt64, count: Int) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        try lease.check()
        guard !closed, offset <= info.byteCount, count >= 0, count <= MediaFormat.chunkSize else { throw VaultError.damaged }
        let wanted = Int(min(UInt64(count), info.byteCount - offset))
        var output = Data()
        do {
            while output.count < wanted {
                let position = offset + UInt64(output.count)
                let index = position / UInt64(MediaFormat.chunkSize)
                let within = Int(position % UInt64(MediaFormat.chunkSize))
                var data = try chunk(index)
                defer { data.wipe() }
                let take = min(wanted - output.count, data.count - within)
                output.append(data[within..<within + take])
            }
            try lease.check()
            return output
        } catch { output.wipe(); throw error }
    }
    func verifyAll() throws {
        lock.lock(); defer { lock.unlock() }
        var index: UInt64 = 0
        while index * UInt64(MediaFormat.chunkSize) < info.byteCount {
            var plain = try chunk(index)
            plain.wipe()
            index += 1
        }
    }
    func close() {
        lock.lock(); defer { lock.unlock() }
        if !closed { closed = true; key.destroy(); try? handle.close() }
    }
    deinit { close() }
}
