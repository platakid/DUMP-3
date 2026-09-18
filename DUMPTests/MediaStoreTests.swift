import XCTest
@testable import DUMP

final class MediaStoreTests: XCTestCase {
    private var store: MediaStore!
    private var lease: SessionLease!
    private var master: SecretBytes!
    override func setUpWithError() throws {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        store = try MediaStore(directory: base.appendingPathComponent("DUMPTests-" + UUID().uuidString))
        lease = SessionLease()
        master = try lease.own(AESBox.generateKey())
    }
    override func tearDownWithError() throws {
        lease.revoke()
        try FileManager.default.removeItem(at: store.directory)
    }
    private func fixture() throws -> (MediaInfo, Data) {
        let data = Data((0..<(2 * MediaFormat.chunkSize + 137)).map { UInt8(truncatingIfNeeded: $0 * 31) })
        let writer = try MediaWriter(store: store, master: master, lease: lease)
        for offset in stride(from: 0, to: data.count, by: 173123) {
            try writer.append(data.subdata(in: offset..<min(offset + 173123, data.count)))
        }
        return (try writer.finish(name: "fixture.bin", typeIdentifier: "public.data"), data)
    }
    private func reader(_ item: MediaInfo) throws -> MediaReader {
        try MediaReader(url: store.url(item.id), id: item.id, master: master, lease: lease)
    }
    func testRoundTripByteIdenticalAndRandomAccess() throws {
        let (item, original) = try fixture()
        let input = try reader(item); defer { input.close() }
        var result = Data(); defer { result.wipe() }
        for offset in stride(from: 0, to: original.count, by: 97991) {
            result.append(try input.read(offset: UInt64(offset), count: min(97991, original.count - offset)))
        }
        XCTAssertEqual(result, original)
        let offset = MediaFormat.chunkSize - 5
        XCTAssertEqual(try input.read(offset: UInt64(offset), count: 19), original.subdata(in: offset..<(offset + 19)))
    }
    func testAllStoredFilesExcludedFromBackupIncludingPartial() throws {
        _ = try fixture()
        let writer = try MediaWriter(store: store, master: master, lease: lease)
        try writer.append(Data([1, 2, 3]))
        let files = try FileManager.default.contentsOfDirectory(at: store.directory, includingPropertiesForKeys: nil)
        XCTAssertEqual(files.count, 2)
        for url in files + [store.directory] {
            XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
        }
        withExtendedLifetime(writer) {}
    }
    func testTamperingRejected() throws {
        let (item, _) = try fixture()
        let file = try FileHandle(forUpdating: store.url(item.id)); defer { try? file.close() }
        let offset = UInt64(MediaFormat.headerSize + 40)
        try file.seek(toOffset: offset)
        var byte = try XCTUnwrap(file.read(upToCount: 1)); byte[0] ^= 1
        try file.seek(toOffset: offset); try file.write(contentsOf: byte)
        let input = try reader(item); defer { input.close() }
        XCTAssertThrowsError(try input.verifyAll())
    }
    func testTruncationRejected() throws {
        let (item, _) = try fixture()
        let file = try FileHandle(forUpdating: store.url(item.id)); defer { try? file.close() }
        let end = try file.seekToEnd(); try file.truncate(atOffset: end - 1)
        XCTAssertThrowsError(try reader(item))
    }
    func testReorderedChunksRejected() throws {
        let (item, _) = try fixture()
        let file = try FileHandle(forUpdating: store.url(item.id)); defer { try? file.close() }
        let length = MediaFormat.chunkSize + MediaFormat.overhead
        try file.seek(toOffset: UInt64(MediaFormat.headerSize))
        let first = try XCTUnwrap(file.read(upToCount: length))
        let second = try XCTUnwrap(file.read(upToCount: length))
        try file.seek(toOffset: UInt64(MediaFormat.headerSize))
        try file.write(contentsOf: second); try file.write(contentsOf: first)
        let input = try reader(item); defer { input.close() }
        XCTAssertThrowsError(try input.verifyAll())
    }
    func testRevokedReaderCannotDecrypt() throws {
        let (item, _) = try fixture()
        let input = try reader(item); defer { input.close() }
        lease.revoke()
        XCTAssertThrowsError(try input.read(offset: 0, count: 16))
    }
    func testExportCleanupOnSuccessAndFailure() async throws {
        let (item, original) = try fixture()
        for fail in [false, true] {
            var temporaryURL: URL?
            let result = await PhotosExporter.perform(item: item, store: store, master: master, lease: lease, suffix: "bin") { url in
                temporaryURL = url
                XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
                let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
                XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
                var data = try Data(contentsOf: url); defer { data.wipe() }
                XCTAssertEqual(data, original)
                if fail { throw VaultError.unavailable }
                return true
            }
            XCTAssertEqual(result.exported, !fail)
            XCTAssertEqual(result.cleanup, .removed)
            let url = try XCTUnwrap(temporaryURL)
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
            XCTAssertTrue(FileManager.default.fileExists(atPath: store.url(item.id).path))
        }
    }
}
