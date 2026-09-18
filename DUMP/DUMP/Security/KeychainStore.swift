import Foundation
import Security

struct KeyRecord: Codable {
    var version = 1
    var verificationHash: String
    var wrappingSalt: Data
    var parameters: KDFParameters
    var wrappedKey: Data?
}

protocol KeyRecordStore {
    func read() throws -> KeyRecord?
    func insert(_ record: KeyRecord) throws
    func update(_ record: KeyRecord) throws
}

struct KeychainStore: KeyRecordStore {
    let service = "local.dump.key-record.v1"
    // A single item makes passcode change atomic across hash, salt and wrapped key.
    var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "vault",
         kSecAttrSynchronizable as String: false]
    }
    func read() throws -> KeyRecord? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        // func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
        // https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw VaultError.storage }
        let record = try JSONDecoder().decode(KeyRecord.self, from: data)
        guard record.version == 1 else { throw VaultError.damaged }
        return record
    }
    func insert(_ record: KeyRecord) throws {
        var q = query
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        q[kSecValueData as String] = try JSONEncoder().encode(record)
        // Exact addition query is q: class, service, account, synchronizable=false,
        // accessible=WhenPasscodeSetThisDeviceOnly, valueData=encoded wrapped record.
        // func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
        // https://developer.apple.com/documentation/security/secitemadd(_:_:)
        guard SecItemAdd(q as CFDictionary, nil) == errSecSuccess else { throw VaultError.storage }
    }
    func update(_ record: KeyRecord) throws {
        let changes: [String: Any] = [
            kSecValueData as String: try JSONEncoder().encode(record),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        // func SecItemUpdate(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus
        // https://developer.apple.com/documentation/security/secitemupdate(_:_:)
        guard SecItemUpdate(query as CFDictionary, changes as CFDictionary) == errSecSuccess else { throw VaultError.storage }
    }
}

/// Called on a dedicated worker actor, never on the UI thread.
actor Credentials {
    private let store: KeyRecordStore
    private let hasMedia: () throws -> Bool
    private let wrapAAD = Data("DUMP/master-key/v1".utf8)
    init(store: KeyRecordStore = KeychainStore(), hasMedia: @escaping () throws -> Bool) {
        self.store = store; self.hasMedia = hasMedia
    }
    func exists(lease: SessionLease) throws -> Bool {
        try lease.check()
        let record = try store.read()
        if record == nil, try hasMedia() { throw VaultError.damaged }
        return record != nil
    }
    func create(password: SecretBytes, confirmation: SecretBytes, lease: SessionLease) throws -> SecretBytes {
        defer { password.destroy(); confirmation.destroy() }
        try lease.check()
        guard try store.read() == nil, try !hasMedia() else { throw VaultError.damaged }
        try PasswordHash.validate(password)
        let hash = try PasswordHash.create(password)
        guard try PasswordHash.verify(confirmation, hash: hash) else { throw VaultError.mismatch }
        let salt = try SodiumRuntime.randomSalt()
        var record = KeyRecord(verificationHash: hash, wrappingSalt: salt, parameters: .current)
        // Persist ONLY the verifier/salt first. An interrupted setup remains recoverable
        // by verifying this passcode, but can never reset an existing media library.
        try lease.commit { try store.insert(record) }
        let key = try lease.own(AESBox.generateKey())
        do {
            record.wrappedKey = try wrap(key, password: password, record: record, lease: lease)
            try lease.commit { try store.update(record) }
            return key
        } catch { key.destroy(); throw error }
    }
    func unlock(password: SecretBytes, lease: SessionLease) throws -> SecretBytes {
        defer { password.destroy() }
        try lease.check()
        guard var record = try store.read() else { throw VaultError.damaged }
        guard try PasswordHash.verify(password, hash: record.verificationHash) else { throw VaultError.invalidPassword }
        try lease.check() // Gate 2 has succeeded; only now derive and unwrap.
        if let wrapped = record.wrappedKey {
            let wrappingKey = try lease.own(PasswordHash.derive(password, salt: record.wrappingSalt, parameters: record.parameters))
            defer { wrappingKey.destroy() }
            var plain = try AESBox.open(wrapped, key: wrappingKey, aad: wrapAAD)
            defer { plain.wipe() }
            guard plain.count == 32 else { throw VaultError.damaged }
            return try lease.own(SecretBytes(plain))
        }
        // Recovery only from the hash-saved stage of first setup; not a reset/bypass.
        guard try !hasMedia() else { throw VaultError.damaged }
        let key = try lease.own(AESBox.generateKey())
        do {
            record.wrappedKey = try wrap(key, password: password, record: record, lease: lease)
            try lease.commit { try store.update(record) }
            return key
        } catch { key.destroy(); throw error }
    }
    func change(old: SecretBytes, new: SecretBytes, confirmation: SecretBytes, lease: SessionLease) throws {
        defer { old.destroy(); new.destroy(); confirmation.destroy() }
        try PasswordHash.validate(new)
        // Re-check the current passcode through the same verification/unwrap path.
        let key = try unlock(password: old, lease: lease)
        defer { key.destroy() }
        let hash = try PasswordHash.create(new)
        guard try PasswordHash.verify(confirmation, hash: hash) else { throw VaultError.mismatch }
        var record = KeyRecord(verificationHash: hash, wrappingSalt: try SodiumRuntime.randomSalt(), parameters: .current)
        record.wrappedKey = try wrap(key, password: new, record: record, lease: lease)
        try lease.commit { try store.update(record) }
    }
    private func wrap(_ key: SecretBytes, password: SecretBytes, record: KeyRecord, lease: SessionLease) throws -> Data {
        let wrappingKey = try lease.own(PasswordHash.derive(password, salt: record.wrappingSalt, parameters: record.parameters))
        defer { wrappingKey.destroy() }
        var raw = try key.copyData()
        defer { raw.wipe() }
        return try AESBox.seal(raw, key: wrappingKey, aad: wrapAAD)
    }
}
