import Foundation
import Photos
import UniformTypeIdentifiers
import Darwin

struct ExportOutcome {
    var exported: Bool
    var cleanup: TemporaryExport.Cleanup
}

/// The ONLY exception to the no-plaintext-files rule, explicitly approved for export.
/// Does not promise physical secure erasure or cleanup after process termination.
final class TemporaryExport {
    enum Cleanup: Equatable { case removed, removedWithoutOverwrite, removalFailed }
    let url: URL
    private let handle: FileHandle
    private var cleaned = false
    init(extension suffix: String) throws {
        let safeSuffix = suffix.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) } ? suffix : "bin"
        url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("DUMP-export-" + UUID().uuidString).appendingPathExtension(safeSuffix)
        let fd = Darwin.open(url.path, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, mode_t(0o600))
        guard fd >= 0 else { throw VaultError.storage }
        handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            // Empty file only until all protection attributes have been applied.
            try MediaStore.protect(url)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: url)
            throw error
        }
    }
    func write(reader: MediaReader, lease: SessionLease) throws {
        var offset: UInt64 = 0
        while offset < reader.info.byteCount {
            try lease.check()
            try Task.checkCancellation()
            var plain = try reader.read(offset: offset, count: Int(min(UInt64(MediaFormat.chunkSize), reader.info.byteCount - offset)))
            defer { plain.wipe() }
            guard !plain.isEmpty else { throw VaultError.damaged }
            try handle.write(contentsOf: plain)
            offset += UInt64(plain.count)
        }
        try handle.synchronize()
        try lease.check()
    }
    /// Always attempts unlink even when overwrite fails (e.g. protection is locked).
    /// Logical overwrite cannot guarantee erasure on APFS/flash/copy-on-write storage.
    @discardableResult func cleanup() -> Cleanup {
        if cleaned { return .removed }
        cleaned = true
        var overwriteSucceeded = true
        do {
            let length = try handle.seekToEnd()
            try handle.seek(toOffset: 0)
            let zeros = Data(repeating: 0, count: 65_536)
            var offset: UInt64 = 0
            while offset < length {
                let count = Int(min(UInt64(zeros.count), length - offset))
                try handle.write(contentsOf: zeros.prefix(count))
                offset += UInt64(count)
            }
            try handle.synchronize()
        } catch { overwriteSucceeded = false }
        try? handle.close()
        do { try FileManager.default.removeItem(at: url) }
        catch { return .removalFailed }
        return overwriteSucceeded ? .removed : .removedWithoutOverwrite
    }
    deinit { if !cleaned { cleanup() } } // Normal unwinding only; not a crash guarantee.
}

enum PhotosExporter {
    static func run(item: MediaInfo, store: MediaStore, master: SecretBytes, lease: SessionLease) async throws -> ExportOutcome {
        try lease.check()
        guard let type = UTType(item.typeIdentifier), type.conforms(to: .image) || type.conforms(to: .movie) else { throw VaultError.unavailable }
        return await perform(item: item, store: store, master: master, lease: lease, suffix: type.preferredFilenameExtension ?? "bin") { url in
            try lease.check()
            let state = ExportCommitState()
            try await PHPhotoLibrary.shared().performChanges {
                do {
                    try lease.commit {
                        let request = PHAssetCreationRequest.forAsset()
                        let options = PHAssetResourceCreationOptions()
                        options.shouldMoveFile = false // Retain our file until we overwrite/delete it.
                        options.uniformTypeIdentifier = item.typeIdentifier
                        options.originalFilename = item.name
                        request.addResource(with: type.conforms(to: .movie) ? .video : .photo, fileURL: url, options: options)
                        state.markCommitted()
                    }
                } catch { /* No Photos asset request is made with a revoked lease. */ }
            }
            return state.didCommit
        }
    }
    /// Injectable handoff permits testing cleanup without writing into a user's Photos.
    static func perform(item: MediaInfo, store: MediaStore, master: SecretBytes, lease: SessionLease,
                        suffix: String, handoff: (URL) async throws -> Bool) async -> ExportOutcome {
        var result = ExportOutcome(exported: false, cleanup: .removed)
        // The nested scope guarantees cleanup before returning on success OR any thrown error.
        do {
            let temporary = try TemporaryExport(extension: suffix)
            defer { result.cleanup = temporary.cleanup() }
            let reader = try MediaReader(url: store.url(item.id), id: item.id, master: master, lease: lease)
            defer { reader.close() }
            try temporary.write(reader: reader, lease: lease)
            reader.close() // Release the resource key before handing plaintext to Photos.
            try lease.check()
            result.exported = try await handoff(temporary.url)
        } catch {
            // Cleanup ran before reaching this catch; no destinations/content are logged.
            result.exported = false
        }
        return result
    }
}

private final class ExportCommitState: @unchecked Sendable {
    private let lock = NSLock()
    private var committed = false
    func markCommitted() { lock.withLock { committed = true } }
    var didCommit: Bool { lock.withLock { committed } }
}
