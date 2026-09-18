import Foundation
import Security

// MARK: - Persistent credential record

struct KeyRecord: Codable {

    /// Increment this only when the serialized record format changes.
    var version = 1

    /// Argon2id verifier.
    ///
    /// This verifies that the supplied password is correct, but it is NOT
    /// the vault encryption key.
    var verificationHash: String

    /// Independent random salt used to derive the master-key wrapping key.
    var wrappingSalt: Data

    /// Exact Argon2id parameters used for the wrapping key.
    var parameters: KDFParameters

    /// Random 256-bit vault master key encrypted by a password-derived key.
    ///
    /// nil is permitted only during the narrow interrupted-first-setup state.
    var wrappedKey: Data?
}


// MARK: - Storage abstraction

protocol KeyRecordStore {

    func read() throws -> KeyRecord?

    func insert(_ record: KeyRecord) throws

    func update(_ record: KeyRecord) throws
}


// MARK: - Keychain implementation

struct KeychainStore: KeyRecordStore {

    private let service = "local.dump.key-record.v1"
    private let account = "vault"

    /// One Keychain item deliberately contains:
    ///
    /// - password verifier
    /// - wrapping salt
    /// - KDF parameters
    /// - encrypted master key
    ///
    /// This avoids inconsistent independent Keychain records.
    private var query: [String: Any] {
        [
            kSecClass as String:
                kSecClassGenericPassword,

            kSecAttrService as String:
                service,

            kSecAttrAccount as String:
                account,

            // Never synchronize vault credentials through iCloud Keychain.
            kSecAttrSynchronizable as String:
                false
        ]
    }


    // MARK: Read

    func read() throws -> KeyRecord? {

        var request = query

        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?

        let status = SecItemCopyMatching(
            request as CFDictionary,
            &result
        )

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess,
              let data = result as? Data
        else {
            throw VaultError.storage
        }

        let record: KeyRecord

        do {
            record = try JSONDecoder().decode(
                KeyRecord.self,
                from: data
            )
        } catch {
            throw VaultError.damaged
        }

        try validate(record)

        return record
    }


    // MARK: Insert

    func insert(_ record: KeyRecord) throws {

        try validate(record)

        var request = query

        /*
         Security properties:

         WhenPasscodeSetThisDeviceOnly means:

         - device passcode must be configured
         - item does not migrate to another device
         - item is not restored onto another device from backup
         - removing the device passcode destroys access to this class
         - iCloud Keychain synchronization is disabled separately above
         */

        request[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly

        request[kSecValueData as String] =
            try encode(record)

        let status = SecItemAdd(
            request as CFDictionary,
            nil
        )

        guard status == errSecSuccess else {

            // Never silently overwrite an unexpected existing vault record.
            if status == errSecDuplicateItem {
                throw VaultError.damaged
            }

            throw VaultError.storage
        }
    }


    // MARK: Update

    func update(_ record: KeyRecord) throws {

        try validate(record)

        let changes: [String: Any] = [

            kSecValueData as String:
                try encode(record),

            kSecAttrAccessible as String:
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,

            kSecAttrSynchronizable as String:
                false
        ]

        let status = SecItemUpdate(
            query as CFDictionary,
            changes as CFDictionary
        )

        guard status == errSecSuccess else {

            if status == errSecItemNotFound {
                throw VaultError.damaged
            }

            throw VaultError.storage
        }
    }


    // MARK: Validation

    private func validate(
        _ record: KeyRecord
    ) throws {

        guard record.version == 1 else {
            throw VaultError.damaged
        }

        guard record.verificationHash.hasPrefix("$argon2id$"),
              record.verificationHash.utf8.count < 128,
              !record.verificationHash.utf8.contains(0)
        else {
            throw VaultError.damaged
        }

        guard record.wrappingSalt.count == 16 else {
            throw VaultError.damaged
        }

        /*
         Do not accept attacker-controlled KDF parameters.

         Otherwise a modified Keychain record could request weaker
         parameters or absurd parameters intended to exhaust resources.
        */

        guard record.parameters == .current else {
            throw VaultError.damaged
        }

        /*
         AES-GCM combined representation contains:

         12-byte nonce
         ciphertext
         16-byte authentication tag

         The wrapped plaintext is exactly one 32-byte master key.

         Therefore the expected combined size is:

         12 + 32 + 16 = 60 bytes
        */

        if let wrapped = record.wrappedKey {

            guard wrapped.count == 60 else {
                throw VaultError.damaged
            }
        }
    }


    // MARK: Encoding

    private func encode(
        _ record: KeyRecord
    ) throws -> Data {

        do {
            return try JSONEncoder().encode(record)
        } catch {
            throw VaultError.storage
        }
    }
}


// MARK: - Credential manager

/// All expensive credential operations run away from the UI actor.
///
/// The password NEVER becomes the vault master key.
///
/// Architecture:
///
/// password
///     ↓
/// Argon2id
///     ↓
/// password-derived wrapping key
///     ↓
/// AES-GCM unwrap
///     ↓
/// random 256-bit vault master key
///
/// Therefore changing a boolean such as "authenticated = true"
/// cannot manufacture the vault encryption key.
actor Credentials {

    private let store: KeyRecordStore

    /// Returns true when encrypted media already exists.
    ///
    /// This prevents deleting/corrupting the credential record from
    /// turning an existing vault into a fresh setup.
    private let hasMedia: () throws -> Bool

    /// Domain separation for the encrypted master key.
    private let wrapAAD =
        Data("DUMP/master-key/v1".utf8)


    init(
        store: KeyRecordStore = KeychainStore(),
        hasMedia: @escaping () throws -> Bool
    ) {

        self.store = store
        self.hasMedia = hasMedia
    }


    // MARK: Existence

    func exists(
        lease: SessionLease
    ) throws -> Bool {

        try lease.check()

        let record = try store.read()

        /*
         Encrypted media without its credential record must NEVER
         be interpreted as an empty/new vault.

         That would create dangerous reset/bypass behavior.
        */

        if record == nil,
           try hasMedia() {

            throw VaultError.damaged
        }

        return record != nil
    }


    // MARK: Create vault

    func create(
        password: SecretBytes,
        confirmation: SecretBytes,
        lease: SessionLease
    ) throws -> SecretBytes {

        defer {
            password.destroy()
            confirmation.destroy()
        }

        try lease.check()

        /*
         Vault creation is permitted ONLY when both credential storage
         and encrypted-media storage are empty.
        */

        guard try store.read() == nil,
              try !hasMedia()
        else {
            throw VaultError.damaged
        }

        try PasswordHash.validate(password)

        /*
         Create an independent Argon2id verifier.

         libsodium generates its own random salt for this verifier.
        */

        let verificationHash =
            try PasswordHash.create(password)

        /*
         Confirmation must pass the exact same cryptographic verifier.
         We don't compare Swift Strings containing the passwords.
        */

        guard try PasswordHash.verify(
            confirmation,
            hash: verificationHash
        )
        else {
            throw VaultError.mismatch
        }

        try lease.check()

        /*
         Separate random salt for deriving the master-key wrapping key.

         The verifier salt and wrapping salt therefore serve
         independent purposes.
        */

        let wrappingSalt =
            try SodiumRuntime.randomSalt()

        var record = KeyRecord(
            verificationHash: verificationHash,
            wrappingSalt: wrappingSalt,
            parameters: .current,
            wrappedKey: nil
        )

        /*
         Persist the verifier/salt first.

         This deliberately supports recovery from an interruption
         occurring between credential creation and generation of the
         first master key.

         This state may be recovered ONLY while no encrypted media exists.
        */

        try lease.commit {
            try store.insert(record)
        }

        try lease.check()

        /*
         Generate the vault master key randomly.

         It is NOT derived directly from the password.
        */

        let masterKey =
            try lease.own(
                AESBox.generateKey()
            )

        do {

            record.wrappedKey =
                try wrap(
                    masterKey,
                    password: password,
                    record: record,
                    lease: lease
                )

            /*
             Commit the encrypted master key atomically into
             the existing Keychain item.
            */

            try lease.commit {
                try store.update(record)
            }

            return masterKey

        } catch {

            masterKey.destroy()

            throw error
        }
    }


    // MARK: Unlock vault

    func unlock(
        password: SecretBytes,
        lease: SessionLease
    ) throws -> SecretBytes {

        defer {
            password.destroy()
        }

        try lease.check()

        guard var record =
                try store.read()
        else {
            throw VaultError.damaged
        }

        /*
         Gate 1:
         Verify the password using Argon2id.

         No wrapping key is derived before this succeeds.
        */

        guard try PasswordHash.verify(
            password,
            hash: record.verificationHash
        )
        else {
            throw VaultError.invalidPassword
        }

        try lease.check()

        /*
         Normal vault state.
        */

        if let wrapped =
            record.wrappedKey {

            /*
             Gate 2:
             Independently derive the wrapping key from the password.

             Authentication success alone is insufficient.
            */

            let wrappingKey =
                try lease.own(
                    PasswordHash.derive(
                        password,
                        salt: record.wrappingSalt,
                        parameters: record.parameters
                    )
                )

            defer {
                wrappingKey.destroy()
            }

            /*
             AES-GCM authenticates both:

             - the encrypted master key
             - its vault-specific AAD

             A modified wrapped key therefore fails authentication.
            */

            var plaintext: Data

            do {

                plaintext =
                    try AESBox.open(
                        wrapped,
                        key: wrappingKey,
                        aad: wrapAAD
                    )

            } catch {

                throw VaultError.damaged
            }

            defer {
                plaintext.wipe()
            }

            guard plaintext.count == 32 else {
                throw VaultError.damaged
            }

            try lease.check()

            return try lease.own(
                SecretBytes(plaintext)
            )
        }


        // MARK: Interrupted initial-setup recovery

        /*
         wrappedKey == nil is legal ONLY if no encrypted media exists.

         This is NOT a password-reset mechanism.

         If encrypted media already exists, a missing wrapped key means
         the vault is damaged and must fail closed.
        */

        guard try !hasMedia() else {
            throw VaultError.damaged
        }

        try lease.check()

        let masterKey =
            try lease.own(
                AESBox.generateKey()
            )

        do {

            record.wrappedKey =
                try wrap(
                    masterKey,
                    password: password,
                    record: record,
                    lease: lease
                )

            try lease.commit {
                try store.update(record)
            }

            return masterKey

        } catch {

            masterKey.destroy()

            throw error
        }
    }


    // MARK: Change password

    func change(
        old: SecretBytes,
        new: SecretBytes,
        confirmation: SecretBytes,
        lease: SessionLease
    ) throws {

        /*
         unlock() owns destruction of `old`.

         We destroy only the new password and confirmation here.
        */

        defer {
            new.destroy()
            confirmation.destroy()
        }

        try lease.check()

        try PasswordHash.validate(new)

        /*
         Recover the REAL master key using the existing password.

         A password change therefore cannot manufacture a replacement
         master key for an existing vault.
        */

        let masterKey =
            try unlock(
                password: old,
                lease: lease
            )

        defer {
            masterKey.destroy()
        }

        try lease.check()

        let newVerificationHash =
            try PasswordHash.create(new)

        guard try PasswordHash.verify(
            confirmation,
            hash: newVerificationHash
        )
        else {
            throw VaultError.mismatch
        }

        /*
         Generate a fresh independent wrapping salt.

         Password changes therefore create a completely new
         password-derived wrapping key.
        */

        let newWrappingSalt =
            try SodiumRuntime.randomSalt()

        var newRecord = KeyRecord(
            verificationHash: newVerificationHash,
            wrappingSalt: newWrappingSalt,
            parameters: .current,
            wrappedKey: nil
        )

        newRecord.wrappedKey =
            try wrap(
                masterKey,
                password: new,
                record: newRecord,
                lease: lease
            )

        /*
         Only after the new wrapped master key exists do we replace
         the Keychain record.
        */

        try lease.commit {
            try store.update(newRecord)
        }
    }


    // MARK: Master-key wrapping

    private func wrap(
        _ masterKey: SecretBytes,
        password: SecretBytes,
        record: KeyRecord,
        lease: SessionLease
    ) throws -> Data {

        try lease.check()

        /*
         Argon2id converts the password into a 256-bit wrapping key.

         This is intentionally expensive to slow offline guessing.
        */

        let wrappingKey =
            try lease.own(
                PasswordHash.derive(
                    password,
                    salt: record.wrappingSalt,
                    parameters: record.parameters
                )
            )

        defer {
            wrappingKey.destroy()
        }

        var rawMasterKey =
            try masterKey.copyData()

        defer {
            rawMasterKey.wipe()
        }

        guard rawMasterKey.count == 32 else {
            throw VaultError.crypto
        }

        /*
         No nonce is supplied.

         CryptoKit therefore generates a fresh random AES-GCM nonce.
         The nonce is included in the combined sealed representation.
        */

        let wrapped =
            try AESBox.seal(
                rawMasterKey,
                key: wrappingKey,
                aad: wrapAAD
            )

        /*
         Expected AES-GCM combined representation:

         nonce       12 bytes
         ciphertext  32 bytes
         tag         16 bytes

         total       60 bytes
        */

        guard wrapped.count == 60 else {
            throw VaultError.crypto
        }

        return wrapped
    }
}
