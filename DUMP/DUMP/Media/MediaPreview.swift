import SwiftUI
import AVKit
import ImageIO
import UniformTypeIdentifiers

private final class ImageSourceContext {
    let reader: MediaReader
    init(_ reader: MediaReader) { self.reader = reader }
}

enum MemoryImage {
    static func decode(_ reader: MediaReader) throws -> UIImage {
        let retained = Unmanaged.passRetained(ImageSourceContext(reader)).toOpaque()
        var callbacks = CGDataProviderDirectCallbacks(version: 0, getBytePointer: nil,
            releaseBytePointer: nil, getBytesAtPosition: { info, buffer, position, count in
                guard let info, position >= 0 else { return 0 }
                let context = Unmanaged<ImageSourceContext>.fromOpaque(info).takeUnretainedValue()
                var completed = 0
                do {
                    while completed < count {
                        var data = try context.reader.read(offset: UInt64(position) + UInt64(completed), count: min(count - completed, MediaFormat.chunkSize))
                        defer { data.wipe() }
                        if data.isEmpty { break }
                        data.copyBytes(to: buffer.advanced(by: completed).assumingMemoryBound(to: UInt8.self), count: data.count)
                        completed += data.count
                    }
                    return completed
                } catch { return 0 }
            }, releaseInfo: { info in
                if let info { Unmanaged<ImageSourceContext>.fromOpaque(info).release() }
            })
        guard let provider = CGDataProvider(directInfo: retained, size: off_t(reader.info.byteCount), callbacks: &callbacks) else {
            Unmanaged<ImageSourceContext>.fromOpaque(retained).release()
            throw VaultError.unavailable
        }
        let sourceOptions: [CFString: Any] = [kCGImageSourceShouldCache: false]
        guard let source = CGImageSourceCreateWithDataProvider(provider, sourceOptions as CFDictionary),
              let image = CGImageSourceCreateThumbnailAtIndex(source, 0, [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: 2560,
                // These control decoded pixels in memory, not a filesystem cache.
                // Finish decoding before the encrypted reader is closed.
                kCGImageSourceShouldCache: true,
                kCGImageSourceShouldCacheImmediately: true
              ] as CFDictionary) else { throw VaultError.unavailable }
        return UIImage(cgImage: image)
    }
}

/// AVFoundation owns response buffers until their deallocators run. Wiping them
/// immediately after respond(with:) would corrupt playback; wipe on release instead.
final class MemoryVideoLoader: NSObject, AVAssetResourceLoaderDelegate {
    let reader: MediaReader
    let queue = DispatchQueue(label: "local.dump.video", qos: .userInitiated)
    init(reader: MediaReader) { self.reader = reader }
    func resourceLoader(_ resourceLoader: AVAssetResourceLoader, shouldWaitForLoadingOfRequestedResource request: AVAssetResourceLoadingRequest) -> Bool {
        do {
            if let info = request.contentInformationRequest {
                info.contentType = reader.info.typeIdentifier
                info.contentLength = Int64(reader.info.byteCount)
                info.isByteRangeAccessSupported = true
            }
            if let dataRequest = request.dataRequest {
                guard dataRequest.requestedOffset >= 0, dataRequest.requestedLength >= 0 else { throw VaultError.damaged }
                var position = max(dataRequest.requestedOffset, dataRequest.currentOffset)
                let end = dataRequest.requestsAllDataToEndOfResource
                    ? Int64(reader.info.byteCount)
                    : min(Int64(reader.info.byteCount), dataRequest.requestedOffset + Int64(dataRequest.requestedLength))
                guard position <= end else { throw VaultError.damaged }
                while position < end, !request.isCancelled {
                    var plain = try reader.read(offset: UInt64(position), count: Int(min(Int64(MediaFormat.chunkSize), end - position)))
                    defer { plain.wipe() }
                    guard !plain.isEmpty else { throw VaultError.damaged }
                    let memory = UnsafeMutableRawPointer.allocate(byteCount: plain.count, alignment: 16)
                    plain.copyBytes(to: memory.assumingMemoryBound(to: UInt8.self), count: plain.count)
                    let response = Data(bytesNoCopy: memory, count: plain.count, deallocator: .custom { pointer, count in
                        SodiumRuntime.wipe(pointer, count: count)
                        pointer.deallocate()
                    })
                    // Apple documents that the system may retain this data indefinitely:
                    // https://developer.apple.com/documentation/avfoundation/avassetresourceloadingdatarequest/respond(with:)
                    dataRequest.respond(with: response)
                    position += Int64(plain.count)
                }
            }
            if !request.isCancelled { request.finishLoading() }
        } catch { if !request.isCancelled { request.finishLoading(with: error) } }
        return true
    }
    func close() { reader.close() }
}

@MainActor final class MediaPreview: ObservableObject {
    @Published private(set) var item: MediaInfo?
    @Published private(set) var image: UIImage?
    @Published private(set) var player: AVPlayer?
    private var loader: MemoryVideoLoader?
    private var generation: UInt64 = 0
    func clear() {
        generation &+= 1
        player?.pause()
        player?.replaceCurrentItem(with: nil)
        player = nil
        loader?.close(); loader = nil
        image = nil; item = nil
    }
    func open(_ item: MediaInfo, store: MediaStore, master: SecretBytes, lease: SessionLease) async throws {
        clear()
        let ticket = generation
        let reader = try MediaReader(url: store.url(item.id), id: item.id, master: master, lease: lease)
        let type = UTType(item.typeIdentifier)
        if type?.conforms(to: .movie) == true {
            let source = MemoryVideoLoader(reader: reader)
            let asset = AVURLAsset(url: URL(string: "dump-memory://resource/\(item.id.uuidString)")!)
            asset.resourceLoader.setDelegate(source, queue: source.queue)
            try lease.check()
            let playerItem = AVPlayerItem(asset: asset)
            playerItem.preferredForwardBufferDuration = 1
            let playback = AVPlayer(playerItem: playerItem)
            playback.allowsExternalPlayback = false
            loader = source; player = playback; self.item = item
        } else if type?.conforms(to: .image) == true {
            defer { reader.close() }
            let rendered = try await Task.detached { try MemoryImage.decode(reader) }.value
            try lease.check()
            guard generation == ticket else { return }
            image = rendered; self.item = item
        } else { reader.close(); throw VaultError.unavailable }
    }
}
