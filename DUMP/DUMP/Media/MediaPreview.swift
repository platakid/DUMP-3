import SwiftUI
import AVKit
import ImageIO
import UniformTypeIdentifiers


// MARK: - Image streaming context

private final class ImageSourceContext {

    let reader: MediaReader

    init(_ reader: MediaReader) {
        self.reader = reader
    }
}


// MARK: - In-memory image decoding

enum MemoryImage {

    static func decode(
        _ reader: MediaReader
    ) throws -> UIImage {

        guard reader.info.byteCount > 0,
              reader.info.byteCount <= UInt64(Int64.max)
        else {
            throw VaultError.damaged
        }

        /*
         CGDataProvider retains this context until ImageIO releases
         the provider.

         The context owns only the encrypted MediaReader. No plaintext
         filesystem path is created.
        */

        let retained =
            Unmanaged.passRetained(
                ImageSourceContext(reader)
            ).toOpaque()

        var callbacks =
            CGDataProviderDirectCallbacks(
                version: 0,
                getBytePointer: nil,
                releaseBytePointer: nil,

                getBytesAtPosition: {
                    info,
                    buffer,
                    position,
                    count in

                    guard let info,
                          position >= 0,
                          count >= 0
                    else {
                        return 0
                    }

                    if count == 0 {
                        return 0
                    }

                    let context =
                        Unmanaged<ImageSourceContext>
                            .fromOpaque(info)
                            .takeUnretainedValue()

                    let start =
                        UInt64(position)

                    guard start <
                            context.reader.info.byteCount
                    else {
                        return 0
                    }

                    let available =
                        context.reader.info.byteCount -
                        start

                    let requested =
                        min(
                            UInt64(count),
                            available
                        )

                    var completed = 0

                    do {

                        while UInt64(completed) <
                                requested {

                            let remaining =
                                requested -
                                UInt64(completed)

                            let amount =
                                Int(
                                    min(
                                        UInt64(
                                            MediaFormat.chunkSize
                                        ),
                                        remaining
                                    )
                                )

                            guard amount > 0 else {
                                break
                            }

                            var data =
                                try context.reader.read(
                                    offset:
                                        start +
                                        UInt64(completed),
                                    count: amount
                                )

                            defer {
                                data.wipe()
                            }

                            guard !data.isEmpty,
                                  data.count <= amount
                            else {
                                return completed
                            }

                            data.copyBytes(
                                to:
                                    buffer
                                        .advanced(
                                            by: completed
                                        )
                                        .assumingMemoryBound(
                                            to: UInt8.self
                                        ),
                                count:
                                    data.count
                            )

                            completed +=
                                data.count
                        }

                        return completed

                    } catch {

                        return 0
                    }
                },

                releaseInfo: {
                    info in

                    if let info {

                        Unmanaged<ImageSourceContext>
                            .fromOpaque(info)
                            .release()
                    }
                }
            )


        guard let provider =
                CGDataProvider(
                    directInfo: retained,
                    size:
                        off_t(
                            reader.info.byteCount
                        ),
                    callbacks: &callbacks
                )
        else {

            Unmanaged<ImageSourceContext>
                .fromOpaque(retained)
                .release()

            throw VaultError.unavailable
        }


        /*
         Don't eagerly cache the original encoded source.
        */

        let sourceOptions:
            [CFString: Any] = [

                kCGImageSourceShouldCache:
                    false
            ]


        guard let source =
                CGImageSourceCreateWithDataProvider(
                    provider,
                    sourceOptions
                        as CFDictionary
                )
        else {
            throw VaultError.unavailable
        }


        /*
         Decode a bounded preview rather than the original image at
         unlimited resolution.

         This limits the amount of decrypted pixel data retained in
         application memory.

         The decoded UIImage itself is plaintext in RAM while the
         preview is displayed. That is unavoidable for rendering.
        */

        let thumbnailOptions:
            [CFString: Any] = [

                kCGImageSourceCreateThumbnailFromImageAlways:
                    true,

                kCGImageSourceCreateThumbnailWithTransform:
                    true,

                kCGImageSourceThumbnailMaxPixelSize:
                    2560,

                /*
                 Decode now while the authenticated reader remains
                 alive.

                 These settings concern decoded pixels in memory,
                 not a plaintext filesystem cache.
                */

                kCGImageSourceShouldCache:
                    true,

                kCGImageSourceShouldCacheImmediately:
                    true
            ]


        guard let image =
                CGImageSourceCreateThumbnailAtIndex(
                    source,
                    0,
                    thumbnailOptions
                        as CFDictionary
                )
        else {
            throw VaultError.unavailable
        }

        return UIImage(
            cgImage: image
        )
    }
}


// MARK: - In-memory video resource loader

/// AVFoundation may retain response Data after respond(with:) returns.
///
/// Therefore response memory MUST NOT be wiped immediately.
///
/// Each response gets separately allocated memory whose custom Data
/// deallocator wipes the bytes immediately before freeing them.
final class MemoryVideoLoader:
    NSObject,
    AVAssetResourceLoaderDelegate {

    let reader: MediaReader

    let queue =
        DispatchQueue(
            label: "local.dump.video",
            qos: .userInitiated
        )

    private let stateLock =
        NSLock()

    private var closed =
        false


    init(
        reader: MediaReader
    ) {

        self.reader =
            reader
    }


    func resourceLoader(
        _ resourceLoader:
            AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource request:
            AVAssetResourceLoadingRequest
    ) -> Bool {

        stateLock.lock()

        let isClosed =
            closed

        stateLock.unlock()

        guard !isClosed else {

            request.finishLoading(
                with:
                    VaultError.locked
            )

            return true
        }


        do {

            /*
             Supply only the information AVFoundation needs to perform
             byte-range playback.
            */

            if let information =
                request.contentInformationRequest {

                information.contentType =
                    reader.info.typeIdentifier

                guard reader.info.byteCount <=
                        UInt64(Int64.max)
                else {
                    throw VaultError.damaged
                }

                information.contentLength =
                    Int64(
                        reader.info.byteCount
                    )

                information.isByteRangeAccessSupported =
                    true
            }


            if let dataRequest =
                request.dataRequest {

                guard dataRequest.requestedOffset >= 0,
                      dataRequest.currentOffset >= 0,
                      dataRequest.requestedLength >= 0
                else {
                    throw VaultError.damaged
                }


                guard reader.info.byteCount <=
                        UInt64(Int64.max)
                else {
                    throw VaultError.damaged
                }

                let resourceLength =
                    Int64(
                        reader.info.byteCount
                    )

                /*
                 currentOffset can move forward as AVFoundation
                 consumes responses.
                */

                var position =
                    max(
                        dataRequest.requestedOffset,
                        dataRequest.currentOffset
                    )

                guard position <=
                        resourceLength
                else {
                    throw VaultError.damaged
                }


                let end: Int64

                if dataRequest
                    .requestsAllDataToEndOfResource {

                    end =
                        resourceLength

                } else {

                    /*
                     Avoid signed integer overflow from:

                     requestedOffset + requestedLength
                    */

                    let requestedLength =
                        Int64(
                            dataRequest.requestedLength
                        )

                    guard dataRequest.requestedOffset <=
                            Int64.max -
                            requestedLength
                    else {
                        throw VaultError.damaged
                    }

                    end =
                        min(
                            resourceLength,
                            dataRequest.requestedOffset +
                            requestedLength
                        )
                }


                guard position <= end else {
                    throw VaultError.damaged
                }


                while position < end,
                      !request.isCancelled {

                    stateLock.lock()

                    let stop =
                        closed

                    stateLock.unlock()

                    if stop {
                        throw VaultError.locked
                    }


                    let remaining =
                        end -
                        position

                    let amount =
                        Int(
                            min(
                                Int64(
                                    MediaFormat.chunkSize
                                ),
                                remaining
                            )
                        )

                    guard amount > 0 else {
                        throw VaultError.damaged
                    }


                    /*
                     Decrypt at most one MediaFormat.chunkSize buffer.
                    */

                    var plaintext =
                        try reader.read(
                            offset:
                                UInt64(position),
                            count:
                                amount
                        )

                    defer {
                        plaintext.wipe()
                    }


                    guard !plaintext.isEmpty,
                          plaintext.count <= amount
                    else {
                        throw VaultError.damaged
                    }


                    /*
                     AVFoundation may retain the response.

                     Allocate independent response memory so our local
                     plaintext Data can be wiped immediately after
                     copying.
                    */

                    let memory =
                        UnsafeMutableRawPointer
                            .allocate(
                                byteCount:
                                    plaintext.count,
                                alignment: 16
                            )


                    plaintext.copyBytes(
                        to:
                            memory
                                .assumingMemoryBound(
                                    to: UInt8.self
                                ),
                        count:
                            plaintext.count
                    )


                    let response =
                        Data(
                            bytesNoCopy:
                                memory,
                            count:
                                plaintext.count,
                            deallocator:
                                .custom {
                                    pointer,
                                    count in

                                    /*
                                     Wipe the AVFoundation response
                                     buffer at the moment its final Data
                                     owner releases it.
                                    */

                                    SodiumRuntime.wipe(
                                        pointer,
                                        count: count
                                    )

                                    pointer.deallocate()
                                }
                        )


                    if request.isCancelled {

                        /*
                         `response` falls out of scope and its custom
                         deallocator wipes the independent buffer.
                        */

                        break
                    }


                    dataRequest.respond(
                        with: response
                    )

                    position +=
                        Int64(
                            plaintext.count
                        )
                }
            }


            if !request.isCancelled {

                stateLock.lock()

                let stillOpen =
                    !closed

                stateLock.unlock()

                if stillOpen {

                    request.finishLoading()

                } else {

                    request.finishLoading(
                        with:
                            VaultError.locked
                    )
                }
            }

        } catch {

            if !request.isCancelled {

                request.finishLoading(
                    with: error
                )
            }
        }

        return true
    }


    func close() {

        stateLock.lock()

        if closed {

            stateLock.unlock()

            return
        }

        closed = true

        stateLock.unlock()

        /*
         MediaReader.close():

         - destroys the per-resource AES key
         - closes the encrypted file handle

         Any subsequent resource-loader read therefore fails closed.
        */

        reader.close()
    }


    deinit {
        close()
    }
}


// MARK: - Preview controller

@MainActor
final class MediaPreview:
    ObservableObject {

    @Published
    private(set)
    var item: MediaInfo?

    @Published
    private(set)
    var image: UIImage?

    @Published
    private(set)
    var player: AVPlayer?

    private var loader:
        MemoryVideoLoader?

    /*
     Every clear/open cycle changes this value.

     A stale image decode that finishes after clear() therefore cannot
     repopulate the preview.
    */
    private var generation:
        UInt64 = 0


    // MARK: Clear

    func clear() {

        generation &+= 1

        /*
         Stop playback before destroying the resource loader/key.
        */

        player?.pause()

        player?
            .replaceCurrentItem(
                with: nil
            )

        player = nil

        loader?.close()

        loader = nil

        /*
         Release decoded plaintext image pixels held by this model.

         UIKit/CoreGraphics may manage internal copies according to
         system behavior, so this should not be described as a
         guaranteed RAM wipe of every rendered pixel.
        */

        image = nil

        item = nil
    }


    // MARK: Open

    func open(
        _ item: MediaInfo,
        store: MediaStore,
        master: SecretBytes,
        lease: SessionLease
    ) async throws {

        clear()

        let ticket =
            generation

        try lease.check()


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


        guard let type =
                UTType(
                    item.typeIdentifier
                )
        else {

            reader.close()

            throw VaultError.unavailable
        }


        // MARK: Video

        if type.conforms(
            to: .movie
        ) {

            let source =
                MemoryVideoLoader(
                    reader: reader
                )


            /*
             Custom non-file URL.

             AVFoundation must request media through our
             AVAssetResourceLoader rather than accessing a plaintext
             filesystem resource.
            */

            guard let resourceURL =
                    URL(
                        string:
                            "dump-memory://resource/" +
                            item.id.uuidString
                    )
            else {

                source.close()

                throw VaultError.unavailable
            }


            let asset =
                AVURLAsset(
                    url: resourceURL
                )


            asset.resourceLoader
                .setDelegate(
                    source,
                    queue:
                        source.queue
                )


            do {

                try lease.check()

                guard generation ==
                        ticket
                else {

                    source.close()

                    return
                }


                let playerItem =
                    AVPlayerItem(
                        asset: asset
                    )


                /*
                 Keep AVFoundation's forward buffering relatively
                 small because buffered video data is decrypted
                 plaintext in memory.
                */

                playerItem
                    .preferredForwardBufferDuration =
                        1


                let playback =
                    AVPlayer(
                        playerItem:
                            playerItem
                    )


                /*
                 Prevent AirPlay / external playback.

                 Preview stays local to this application/device.
                */

                playback
                    .allowsExternalPlayback =
                        false


                /*
                 Do not automatically route video to an external
                 playback context.
                */

                playback
                    .usesExternalPlaybackWhileExternalScreenIsActive =
                        false


                try lease.check()

                guard generation ==
                        ticket
                else {

                    playback.pause()

                    playback
                        .replaceCurrentItem(
                            with: nil
                        )

                    source.close()

                    return
                }


                loader =
                    source

                player =
                    playback

                self.item =
                    item

            } catch {

                source.close()

                throw error
            }


        // MARK: Image

        } else if type.conforms(
            to: .image
        ) {

            /*
             ImageIO synchronously calls the encrypted reader from the
             detached worker while decoding.

             The reader is closed as soon as decoding completes.
            */

            defer {
                reader.close()
            }


            let rendered =
                try await Task.detached {

                    try MemoryImage.decode(
                        reader
                    )

                }.value


            try lease.check()


            /*
             clear()/lock() may have occurred while ImageIO was
             decoding.

             A stale decode must never restore the old image.
            */

            guard generation ==
                    ticket
            else {
                return
            }


            image =
                rendered

            self.item =
                item


        } else {

            reader.close()

            throw VaultError.unavailable
        }
    }
}
