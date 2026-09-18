import XCTest
@testable import DUMP

final class MemoryRecords: KeyRecordStore {
    var record: KeyRecord?
    var reads = 0
    func read() throws -> KeyRecord? { reads += 1; return record }
    func insert(_ record: KeyRecord) throws {
        guard self.record == nil else { throw VaultError.storage }
        self.record = record
    }
    func update(_ record: KeyRecord) throws {
        guard self.record != nil else { throw VaultError.storage }
        self.record = record
    }
}

@MainActor final class FakeDeviceAuth: DeviceAuthenticating {
    var success = true
    var calls = 0
    var suspended = false
    var continuation: CheckedContinuation<Bool, Never>?
    func authenticate() async throws -> Bool {
        calls += 1
        if suspended { return await withCheckedContinuation { continuation = $0 } }
        return success
    }
    func cancel() {} // Deliberately allow a late callback to test session invalidation.
}

final class SecurityTests: XCTestCase {
    private var store: MediaStore!
    override func setUpWithError() throws {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        store = try MediaStore(directory: base.appendingPathComponent("DUMPSecurityTests-" + UUID().uuidString))
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: store.directory) }

    func testPasswordRuleAndUnicodeVerification() throws {
        XCTAssertThrowsError(try PasswordHash.validate("abcdefgh"))
        XCTAssertThrowsError(try PasswordHash.validate("short1"))
        XCTAssertNoThrow(try PasswordHash.validate("ééééééé1"))
        let password = SecretBytes(password: "ééééééé1")
        let wrong = SecretBytes(password: "different1")
        defer { password.destroy(); wrong.destroy() }
        let hash = try PasswordHash.create(password)
        XCTAssertTrue(hash.hasPrefix("$argon2id$"))
        XCTAssertTrue(try PasswordHash.verify(password, hash: hash))
        XCTAssertFalse(try PasswordHash.verify(wrong, hash: hash))
    }

    func testKeyRevocation() throws {
        let lease = SessionLease()
        let secret = try lease.own(AESBox.generateKey())
        lease.revoke()
        XCTAssertThrowsError(try secret.copyData())
        XCTAssertThrowsError(try lease.check())
        XCTAssertThrowsError(try lease.own(AESBox.generateKey()))
    }

    func testPasscodeChangeKeepsSameMasterKey() async throws {
        let records = MemoryRecords()
        let credentials = Credentials(store: records, hasMedia: { false })
        let lease = SessionLease()
        defer { lease.revoke() }
        let master = try await credentials.create(password: SecretBytes(password: "first-pass1"), confirmation: SecretBytes(password: "first-pass1"), lease: lease)
        var before = try master.copyData()
        defer { before.wipe() }
        try await credentials.change(old: SecretBytes(password: "first-pass1"), new: SecretBytes(password: "second-pass2"), confirmation: SecretBytes(password: "second-pass2"), lease: lease)
        let unlocked = try await credentials.unlock(password: SecretBytes(password: "second-pass2"), lease: lease)
        var after = try unlocked.copyData()
        defer { after.wipe() }
        XCTAssertEqual(before, after)
        do {
            _ = try await credentials.unlock(password: SecretBytes(password: "first-pass1"), lease: lease)
            XCTFail("Old passcode must no longer unlock")
        } catch { XCTAssertTrue(error is VaultError) }
    }

    @MainActor func testGate2UnreachableWhenGate1Fails() async {
        let auth = FakeDeviceAuth(); auth.success = false
        let records = MemoryRecords()
        let model = AppModel(auth: auth, store: store, credentials: Credentials(store: records, hasMedia: { false }))
        XCTAssertTrue(model.unlockDecoy("7002")); model.reveal()
        await model.enter()
        XCTAssertEqual(model.route, .landing)
        XCTAssertEqual(records.reads, 0)
        await model.submit(password: "some-pass1", confirmation: "some-pass1")
        XCTAssertEqual(model.route, .landing)
        XCTAssertNil(records.record)
    }

    @MainActor func testBackgroundRequiresDecoyTriggerAndBothGates() async {
        let auth = FakeDeviceAuth()
        let model = AppModel(auth: auth, store: store, credentials: Credentials(store: MemoryRecords(), hasMedia: { false }))
        XCTAssertTrue(model.unlockDecoy("7002")); model.reveal(); await model.enter()
        XCTAssertEqual(model.route, .setup)
        await model.submit(password: "testing-pass1", confirmation: "testing-pass1")
        XCTAssertEqual(model.route, .vault)
        model.lock()
        XCTAssertEqual(model.route, .decoyLock)
        await model.enter()
        await model.submit(password: "testing-pass1", confirmation: "")
        XCTAssertEqual(model.route, .decoyLock)
        XCTAssertTrue(model.unlockDecoy("7002")); await model.enter()
        XCTAssertEqual(model.route, .notes)
        model.reveal(); await model.enter()
        XCTAssertEqual(model.route, .gate2)
        XCTAssertEqual(auth.calls, 2)
        await model.submit(password: "testing-pass1", confirmation: "")
        XCTAssertEqual(model.route, .vault)
        model.lock()
    }

    @MainActor func testLateGate1SuccessCannotReopenLockedSession() async {
        let auth = FakeDeviceAuth(); auth.suspended = true
        let records = MemoryRecords()
        let model = AppModel(auth: auth, store: store, credentials: Credentials(store: records, hasMedia: { false }))
        XCTAssertTrue(model.unlockDecoy("7002")); model.reveal()
        let task = Task { await model.enter() }
        while auth.continuation == nil { await Task.yield() }
        model.lock()
        auth.continuation?.resume(returning: true)
        await task.value
        XCTAssertEqual(model.route, .decoyLock)
        XCTAssertEqual(records.reads, 0)
    }

    @MainActor func testTriggerRequiresNewNoteAndSingleTrailingSpace() {
        let trigger = "DUMPunlock0715"
        let end = NSRange(location: trigger.utf16.count, length: 0)
        XCTAssertTrue(NoteTextView.triggers(isNew: true, current: trigger, range: end, replacement: " "))
        XCTAssertFalse(NoteTextView.triggers(isNew: false, current: trigger, range: end, replacement: " "))
        XCTAssertFalse(NoteTextView.triggers(isNew: true, current: "", range: NSRange(location: 0, length: 0), replacement: trigger + " "))
        XCTAssertFalse(NoteTextView.triggers(isNew: true, current: trigger, range: end, replacement: "\n"))
    }

    @MainActor func testExportIsUnreachableFromDecoyAndLanding() {
        let model = AppModel(auth: FakeDeviceAuth(), store: store, credentials: Credentials(store: MemoryRecords(), hasMedia: { false }))
        let item = MediaInfo(id: UUID(), name: "example.jpg", typeIdentifier: "public.jpeg", byteCount: 1, importedAt: Date())
        model.requestExport(item); XCTAssertNil(model.exportCandidate)
        XCTAssertTrue(model.unlockDecoy("7002"))
        model.requestExport(item); XCTAssertNil(model.exportCandidate)
        model.reveal()
        model.requestExport(item); XCTAssertNil(model.exportCandidate)
    }
}
