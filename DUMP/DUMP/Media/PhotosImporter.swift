import Foundation
import Photos

final class PhotosImporter: @unchecked Sendable {
    private let lock = NSLock()
    private var active: PHAssetResourceDataRequestID?
    private var cancelled = false
    func cancel() {
        lock.lock(); cancelled = true; let request = active; active = nil; lock.unlock()
        if let request { PHAssetResourceManager.default().cancelDataRequest(request) }
    }
    func run(asset: PHAsset, store: MediaStore, master: SecretBytes, lease: SessionLease) async throws {
        lock.withLock { cancelled = false }
        let resources = PHAssetResource.assetResources(for: asset)
        guard !resources.isEmpty else { throw VaultError.unavailable }
        var completed: [UUID] = []
        do {
            // Preserve every resource, including Live Photo video/RAW/adjustment data.
            // No deletion eligibility if even one resource fails or is cloud-only.
            for resource in resources {
                try lease.check()
                let info = try await importResource(resource, store: store, master: master, lease: lease)
                completed.append(info.id)
            }
            try lease.check()
        } catch {
            // Remove only encrypted files created by this failed import transaction.
            for id in completed { try? FileManager.default.removeItem(at: store.url(id)) }
            throw error
        }
    }
    private func importResource(_ resource: PHAssetResource, store: MediaStore, master: SecretBytes, lease: SessionLease) async throws -> MediaInfo {
        try await withCheckedThrowingContinuation { continuation in
            do {
                let writer = try MediaWriter(store: store, master: master, lease: lease)
                let options = PHAssetResourceRequestOptions()
                options.isNetworkAccessAllowed = false
                var failure: Error?
                let request = PHAssetResourceManager.default().requestData(for: resource, options: options, dataReceivedHandler: { data in
                    guard failure == nil else { return }
                    do { try writer.append(data) } catch { failure = error }
                }, completionHandler: { error in
                    do {
                        if let failure { throw failure }
                        if let error { throw error }
                        try lease.check()
                        let item = try writer.finish(name: resource.originalFilename, typeIdentifier: resource.uniformTypeIdentifier)
                        continuation.resume(returning: item)
                    } catch { continuation.resume(throwing: error) }
                })
                lock.lock()
                active = request
                let shouldCancel = cancelled
                lock.unlock()
                if shouldCancel { PHAssetResourceManager.default().cancelDataRequest(request) }
            } catch { continuation.resume(throwing: error) }
        }
    }
}
