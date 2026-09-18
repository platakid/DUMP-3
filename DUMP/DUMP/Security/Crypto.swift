import Foundation
import CryptoKit
import _Clibsodium

enum VaultError: Error, LocalizedError {
    case locked, invalidPassword, mismatch, passwordRule, damaged, storage, crypto, unavailable

    var errorDescription: String? {
        switch self {
        case .locked:
            return "Session ended. Unlock Note Dump again."
        case .invalidPassword:
            return "The passcode is incorrect."
        case .mismatch:
            return "The passcodes do not match."
        case .passwordRule:
            return "Use at least 16 characters with letters, a number, and a symbol. Maximum 1,024 UTF-8 bytes; no null characters."
        case .damaged:
            return "The protected data could not be verified. Nothing was deleted from Photos."
        case .storage:
            return "Protected storage is unavailable. Check free space and that a device passcode is set."
        case .crypto:
            return "The security operation could not complete. Try again."
        case .unavailable:
            return "This resource is unavailable locally or cannot be displayed."
        }
    }
}

enum SodiumRuntime {
    static let ready: Bool = {
        sodium_init() >= 0
    }()

    static func require() throws {
        guard ready else {
            throw VaultError.crypto
        }
    }

    static func wipe(_ pointer: UnsafeMutableRawPointer, count: Int) {
        sodium_memzero(pointer, count)
    }

    static func equal(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else {
            return false
        }

        if a.isEmpty {
            return true
        }

        return a.withUnsafeBytes { ap in
            b.withUnsafeBytes { bp in
                sodium_memcmp(
                    ap.baseAddress!,
                    bp.baseAddress!,
                    a.count
                ) == 0
            }
        }
    }

    static func randomSalt() throws -> Data {
        try require()

        var data = Data(count: 16)

        data.withUnsafeMutableBytes { pointer in
            randombytes_buf(
                pointer.baseAddress!,
                pointer.count
            )
        }

        return data
    }
}

extension Data {
    mutating func wipe() {
        withUnsafeMutableBytes { pointer in
            if let base = pointer.baseAddress {
                SodiumRuntime.wipe(
                    base,
                    count: pointer.count
                )
            }
        }

        removeAll(keepingCapacity: false)
    }
}

/// An owned allocation for sensitive bytes.
///
/// Copies created internally by Apple frameworks cannot be guaranteed
/// to share this memory and therefore cannot be explicitly wiped here.
final class SecretBytes: @unchecked Sendable {

    private let lock = NSRecursiveLock()
    private let pointer: UnsafeMutableRawPointer

    let count: Int

    private var valid = true

    init(count: Int) {
        self.count = count

        pointer = .allocate(
            byteCount: max(count, 1),
            alignment: 16
        )

        pointer.initializeMemory(
            as: UInt8.self,
            repeating: 0,
            count: max(count, 1)
        )
    }

    convenience init(_ data: Data) {
        self.init(count: data.count)

        data.withUnsafeBytes { source in
            if let base = source.baseAddress {
                pointer.copyMemory(
                    from: base,
                    byteCount: source.count
                )
            }
        }
    }

    convenience init(password: String) {
        var bytes = Data(password.utf8)

        self.init(bytes)

        bytes.wipe()
    }

    func withBytes<T>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> T
    ) throws -> T {

        lock.lock()
        defer { lock.unlock() }

        guard valid else {
            throw VaultError.locked
        }

        return try body(
            .init(
                start: pointer,
                count: count
            )
        )
    }

    func copyData() throws -> Data {
        try withBytes {
            Data($0)
        }
    }

    func destroy() {
        lock.lock()
        defer { lock.unlock() }

        guard valid else {
            return
        }

        SodiumRuntime.wipe(
            pointer,
            count: max(count, 1)
        )

        valid = false
    }

    deinit {
        destroy()
        pointer.deallocate()
    }
}

/// Revocation shared by:
///
/// - KDF operations
/// - vault sessions
/// - file readers
/// - imports
/// - sensitive temporary keys
///
/// Revoking the lease destroys every SecretBytes object registered
/// with the session.
final class SessionLease: @unchecked Sendable {

    private let lock = NSRecursiveLock()

    private var alive = true
    private var secrets: [SecretBytes] = []

    func check() throws {
        lock.lock()
        defer { lock.unlock() }

        guard alive else {
            throw VaultError.locked
        }
    }

    func own(_ secret: SecretBytes) throws -> SecretBytes {
        lock.lock()
        defer { lock.unlock() }

        guard alive else {
            secret.destroy()
            throw VaultError.locked
        }

        secrets.append(secret)

        return secret
    }

    /// Only use for short atomic commits.
    ///
    /// Never hold this lock while performing Argon2,
    /// media decoding, or other expensive operations.
    func commit<T>(
        _ body: () throws -> T
    ) throws -> T {

        lock.lock()
        defer { lock.unlock() }

        guard alive else {
            throw VaultError.locked
        }

        return try body()
    }

    func revoke() {
        lock.lock()

        alive = false

        let oldSecrets = secrets
        secrets.removeAll()

        lock.unlock()

        oldSecrets.forEach {
            $0.destroy()
        }
    }

    deinit {
        revoke()
    }
}

enum AESBox {

    static func generateKey() -> SecretBytes {

        let key = SymmetricKey(size: .bits256)

        var bytes = key.withUnsafeBytes {
            Data($0)
        }

        defer {
            bytes.wipe()
        }

        return SecretBytes(bytes)
    }

    static func seal(
        _ data: Data,
        key: SecretBytes,
        nonce: Data? = nil,
        aad: Data
    ) throws -> Data {

        try key.withBytes { rawKey in

            let symmetricKey = SymmetricKey(
                data: UnsafeRawBufferPointer(rawKey)
            )

            var gcmNonce: AES.GCM.Nonce?

            if let nonce {
                guard nonce.count == 12 else {
                    throw VaultError.crypto
                }

                gcmNonce = try AES.GCM.Nonce(
                    data: nonce
                )
            }

            let sealed = try AES.GCM.seal(
                data,
                using: symmetricKey,
                nonce: gcmNonce,
                authenticating: aad
            )

            guard let combined = sealed.combined else {
                throw VaultError.crypto
            }

            return combined
        }
    }

    static func open(
        _ data: Data,
        key: SecretBytes,
        aad: Data
    ) throws -> Data {

        try key.withBytes { rawKey in

            let symmetricKey = SymmetricKey(
                data: UnsafeRawBufferPointer(rawKey)
            )

            let sealed = try AES.GCM.SealedBox(
                combined: data
            )

            return try AES.GCM.open(
                sealed,
                using: symmetricKey,
                authenticating: aad
            )
        }
    }
}

struct KDFParameters: Codable, Equatable {

    /// Argon2id v1.3.
    ///
    /// 128 MiB memory
    /// 4 passes
    ///
    /// These parameters intentionally make offline password guessing
    /// substantially more expensive.
    let operations: UInt64
    let memory: Int
    let algorithm: Int32

    static let current = KDFParameters(
        operations: 4,
        memory: 134_217_728,
        algorithm: 2
    )
}

enum PasswordHash {

    static func validate(
        _ password: SecretBytes
    ) throws {

        var bytes = try password.copyData()

        defer {
            bytes.wipe()
        }

        guard let text = String(
            data: bytes,
            encoding: .utf8
        ) else {
            throw VaultError.passwordRule
        }

        try validate(text)
    }

    static func validate(
        _ password: String
    ) throws {

        let utf8 = password.utf8

        guard password.count >= 16,
              utf8.count <= 1024,
              !utf8.contains(0)
        else {
            throw VaultError.passwordRule
        }

        let hasLetter = password.unicodeScalars.contains {
            CharacterSet.letters.contains($0)
        }

        let hasDigit = password.unicodeScalars.contains {
            CharacterSet.decimalDigits.contains($0)
        }

        let hasSpecial = password.unicodeScalars.contains {
            CharacterSet.symbols.contains($0) ||
            CharacterSet.punctuationCharacters.contains($0)
        }

        guard hasLetter,
              hasDigit,
              hasSpecial
        else {
            throw VaultError.passwordRule
        }
    }

    static func create(
        _ password: SecretBytes
    ) throws -> String {

        try SodiumRuntime.require()
        try validate(password)

        var output = [CChar](
            repeating: 0,
            count: 128
        )

        defer {
            output.withUnsafeMutableBytes { buffer in
                if let base = buffer.baseAddress {
                    SodiumRuntime.wipe(
                        base,
                        count: buffer.count
                    )
                }
            }
        }

        let status = try password.withBytes { pointer in

            crypto_pwhash_str(
                &output,
                pointer.baseAddress!
                    .assumingMemoryBound(to: CChar.self),
                UInt64(pointer.count),
                KDFParameters.current.operations,
                KDFParameters.current.memory
            )
        }

        guard status == 0 else {
            throw VaultError.crypto
        }

        let result = String(
            cString: output
        )

        guard result.hasPrefix("$argon2id$") else {
            throw VaultError.crypto
        }

        return result
    }

    /// The only primitive that should be used to verify
    /// the user's vault password.
    static func verify(
        _ password: SecretBytes,
        hash: String
    ) throws -> Bool {

        try SodiumRuntime.require()

        guard hash.hasPrefix("$argon2id$"),
              hash.utf8.count < 128,
              !hash.utf8.contains(0)
        else {
            throw VaultError.damaged
        }

        return try password.withBytes { passwordPointer in

            hash.withCString { hashPointer in

                crypto_pwhash_str_verify(
                    hashPointer,
                    passwordPointer.baseAddress!
                        .assumingMemoryBound(to: CChar.self),
                    UInt64(passwordPointer.count)
                ) == 0
            }
        }
    }

    static func derive(
        _ password: SecretBytes,
        salt: Data,
        parameters: KDFParameters
    ) throws -> SecretBytes {

        try SodiumRuntime.require()

        guard salt.count == 16,
              parameters == .current
        else {
            throw VaultError.damaged
        }

        let derivedKey = SecretBytes(
            count: 32
        )

        do {

            let status = try derivedKey.withBytes { output in

                try password.withBytes { passwordPointer in

                    salt.withUnsafeBytes { saltPointer in

                        crypto_pwhash(
                            output.baseAddress!
                                .assumingMemoryBound(to: UInt8.self),
                            32,
                            passwordPointer.baseAddress!
                                .assumingMemoryBound(to: CChar.self),
                            UInt64(passwordPointer.count),
                            saltPointer.baseAddress!
                                .assumingMemoryBound(to: UInt8.self),
                            parameters.operations,
                            parameters.memory,
                            parameters.algorithm
                        )
                    }
                }
            }

            guard status == 0 else {
                throw VaultError.crypto
            }

            return derivedKey

        } catch {

            derivedKey.destroy()

            throw error
        }
    }
}
