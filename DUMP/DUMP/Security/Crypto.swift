import Foundation
import CryptoKit
import _Clibsodium

enum VaultError: Error, LocalizedError {
    case locked, invalidPassword, mismatch, passwordRule, damaged, storage, crypto, unavailable
    var errorDescription: String? {
        switch self {
        case .locked: return "Session ended. Unlock Note Dump again."
        case .invalidPassword: return "The passcode is incorrect."
        case .mismatch: return "The passcodes do not match."
        case .passwordRule: return "Use at least 8 characters, including a number or symbol. Maximum 1,024 UTF-8 bytes; no null characters."
        case .damaged: return "The protected data could not be verified. Nothing was deleted from Photos."
        case .storage: return "Protected storage is unavailable. Check free space and that a device passcode is set."
        case .crypto: return "The security operation could not complete. Try again."
        case .unavailable: return "This resource is unavailable locally or cannot be displayed."
        }
    }
}

enum SodiumRuntime {
    static let ready: Bool = {
        // int sodium_init(void);
        // https://github.com/jedisct1/libsodium/blob/f6bd9140861ab6806f4a99923888b65477fc4e33/src/libsodium/include/sodium/core.h
        sodium_init() >= 0
    }()
    static func require() throws { guard ready else { throw VaultError.crypto } }
    static func wipe(_ pointer: UnsafeMutableRawPointer, count: Int) {
        // void sodium_memzero(void *const pnt, const size_t len);
        // https://github.com/jedisct1/libsodium/blob/f6bd9140861ab6806f4a99923888b65477fc4e33/src/libsodium/include/sodium/utils.h
        sodium_memzero(pointer, count)
    }
    static func equal(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        if a.isEmpty { return true }
        return a.withUnsafeBytes { ap in b.withUnsafeBytes { bp in
            // int sodium_memcmp(const void *const b1_, const void *const b2_, size_t len);
            // https://github.com/jedisct1/libsodium/blob/f6bd9140861ab6806f4a99923888b65477fc4e33/src/libsodium/include/sodium/utils.h
            sodium_memcmp(ap.baseAddress!, bp.baseAddress!, a.count) == 0
        }}
    }
    static func randomSalt() throws -> Data {
        try require()
        var data = Data(count: 16)
        data.withUnsafeMutableBytes { p in
            // void randombytes_buf(void * const buf, const size_t size);
            // https://github.com/jedisct1/libsodium/blob/f6bd9140861ab6806f4a99923888b65477fc4e33/src/libsodium/include/sodium/randombytes.h
            randombytes_buf(p.baseAddress!, p.count)
        }
        return data
    }
}

extension Data {
    mutating func wipe() {
        withUnsafeMutableBytes { p in
            if let base = p.baseAddress { SodiumRuntime.wipe(base, count: p.count) }
        }
        removeAll(keepingCapacity: false)
    }
}

/// A single owned allocation. Copies made inside Apple frameworks are outside this guarantee.
final class SecretBytes: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let pointer: UnsafeMutableRawPointer
    let count: Int
    private var valid = true
    init(count: Int) {
        self.count = count
        pointer = .allocate(byteCount: max(count, 1), alignment: 16)
        pointer.initializeMemory(as: UInt8.self, repeating: 0, count: max(count, 1))
    }
    convenience init(_ data: Data) {
        self.init(count: data.count)
        data.withUnsafeBytes { p in
            if let base = p.baseAddress { pointer.copyMemory(from: base, byteCount: p.count) }
        }
    }
    convenience init(password: String) {
        var bytes = Data(password.utf8)
        self.init(bytes)
        bytes.wipe()
    }
    func withBytes<T>(_ body: (UnsafeMutableRawBufferPointer) throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        guard valid else { throw VaultError.locked }
        return try body(.init(start: pointer, count: count))
    }
    func copyData() throws -> Data { try withBytes { Data($0) } }
    func destroy() {
        lock.lock(); defer { lock.unlock() }
        SodiumRuntime.wipe(pointer, count: max(count, 1))
        valid = false
    }
    deinit { destroy(); pointer.deallocate() }
}

/// Revocation is shared by KDF work, file readers, imports and the visible session.
final class SessionLease: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var alive = true
    private var secrets: [SecretBytes] = []
    func check() throws {
        lock.lock(); defer { lock.unlock() }
        guard alive else { throw VaultError.locked }
    }
    func own(_ secret: SecretBytes) throws -> SecretBytes {
        lock.lock(); defer { lock.unlock() }
        guard alive else { secret.destroy(); throw VaultError.locked }
        secrets.append(secret)
        return secret
    }
    /// For short commits only, never hold this lock during Argon2 or media decoding.
    func commit<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        guard alive else { throw VaultError.locked }
        return try body()
    }
    func revoke() {
        lock.lock()
        alive = false
        let old = secrets
        secrets.removeAll()
        lock.unlock()
        old.forEach { $0.destroy() }
    }
    deinit { revoke() }
}

enum AESBox {
    static func generateKey() -> SecretBytes {
        // init(size: SymmetricKeySize)
        // https://developer.apple.com/documentation/cryptokit/symmetrickey/init(size:)
        let key = SymmetricKey(size: .bits256)
        // func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
        // https://developer.apple.com/documentation/foundation/contiguousbytes/withunsafebytes(_:)
        var bytes = key.withUnsafeBytes { Data($0) }
        defer { bytes.wipe() }
        return SecretBytes(bytes)
    }
    static func seal(_ data: Data, key: SecretBytes, nonce: Data? = nil, aad: Data) throws -> Data {
        try key.withBytes { raw in
            // init<D>(data: D) where D : ContiguousBytes
            // https://developer.apple.com/documentation/cryptokit/symmetrickey/init(data:)
            let symmetric = SymmetricKey(data: UnsafeRawBufferPointer(raw))
            var n: AES.GCM.Nonce?
            if let nonce {
                // init<D>(data: D) throws where D : DataProtocol
                // https://developer.apple.com/documentation/cryptokit/aes/gcm/nonce/init(data:)
                n = try AES.GCM.Nonce(data: nonce)
            }
            // static func seal<Plaintext, AuthenticatedData>(_ message: Plaintext, using key: SymmetricKey, nonce: AES.GCM.Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> AES.GCM.SealedBox where Plaintext : DataProtocol, AuthenticatedData : DataProtocol
            // https://developer.apple.com/documentation/cryptokit/aes/gcm/seal(_:using:nonce:authenticating:)
            let box = try AES.GCM.seal(data, using: symmetric, nonce: n, authenticating: aad)
            guard let combined = box.combined else { throw VaultError.crypto }
            return combined
        }
    }
    static func open(_ data: Data, key: SecretBytes, aad: Data) throws -> Data {
        try key.withBytes { raw in
            // init<D>(data: D) where D : ContiguousBytes
            // https://developer.apple.com/documentation/cryptokit/symmetrickey/init(data:)
            let symmetric = SymmetricKey(data: UnsafeRawBufferPointer(raw))
            // init<D>(combined: D) throws where D : DataProtocol
            // https://developer.apple.com/documentation/cryptokit/aes/gcm/sealedbox/init(combined:)
            let box = try AES.GCM.SealedBox(combined: data)
            // static func open<AuthenticatedData>(_ sealedBox: AES.GCM.SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data where AuthenticatedData : DataProtocol
            // https://developer.apple.com/documentation/cryptokit/aes/gcm/open(_:using:authenticating:)
            return try AES.GCM.open(box, using: symmetric, authenticating: aad)
        }
    }
}

struct KDFParameters: Codable, Equatable {
    // Argon2id v1.3; 64 MiB and 3 passes. Fixed, recorded, never silently downgraded.
    let operations: UInt64
    let memory: Int
    let algorithm: Int32
    static let current = KDFParameters(operations: 3, memory: 67_108_864, algorithm: 2)
}

enum PasswordHash {
    static func validate(_ password: SecretBytes) throws {
        var bytes = try password.copyData()
        defer { bytes.wipe() }
        guard let text = String(data: bytes, encoding: .utf8) else { throw VaultError.passwordRule }
        try validate(text)
    }
    static func validate(_ password: String) throws {
        let special = CharacterSet.decimalDigits.union(.symbols).union(.punctuationCharacters)
        guard password.count >= 8, password.utf8.count <= 1024,
              !password.utf8.contains(0), password.unicodeScalars.contains(where: special.contains)
        else { throw VaultError.passwordRule }
    }
    static func create(_ password: SecretBytes) throws -> String {
        try SodiumRuntime.require()
        var output = [CChar](repeating: 0, count: 128)
        defer { output.withUnsafeMutableBytes { SodiumRuntime.wipe($0.baseAddress!, count: $0.count) } }
        let status = try password.withBytes { p in
            // int crypto_pwhash_str(char out[crypto_pwhash_STRBYTES], const char * const passwd, unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit);
            // https://github.com/jedisct1/libsodium/blob/f6bd9140861ab6806f4a99923888b65477fc4e33/src/libsodium/include/sodium/crypto_pwhash.h
            crypto_pwhash_str(&output, p.baseAddress!.assumingMemoryBound(to: CChar.self), UInt64(p.count), KDFParameters.current.operations, KDFParameters.current.memory)
        }
        guard status == 0 else { throw VaultError.crypto }
        let result = String(cString: output)
        guard result.hasPrefix("$argon2id$") else { throw VaultError.crypto }
        return result
    }
    /// The ONLY vault-password verification primitive, also used for confirmation and changes.
    static func verify(_ password: SecretBytes, hash: String) throws -> Bool {
        try SodiumRuntime.require()
        guard hash.hasPrefix("$argon2id$"), hash.utf8.count < 128, !hash.utf8.contains(0) else { throw VaultError.damaged }
        return try password.withBytes { p in hash.withCString { h in
            // int crypto_pwhash_str_verify(const char *str, const char * const passwd, unsigned long long passwdlen);
            // https://github.com/jedisct1/libsodium/blob/f6bd9140861ab6806f4a99923888b65477fc4e33/src/libsodium/include/sodium/crypto_pwhash.h
            crypto_pwhash_str_verify(h, p.baseAddress!.assumingMemoryBound(to: CChar.self), UInt64(p.count)) == 0
        }}
    }
    static func derive(_ password: SecretBytes, salt: Data, parameters: KDFParameters) throws -> SecretBytes {
        try SodiumRuntime.require()
        guard salt.count == 16, parameters == .current else { throw VaultError.damaged }
        let key = SecretBytes(count: 32)
        do {
            let status = try key.withBytes { out in try password.withBytes { p in salt.withUnsafeBytes { s in
                // int crypto_pwhash(unsigned char * const out, unsigned long long outlen, const char * const passwd, unsigned long long passwdlen, const unsigned char * const salt, unsigned long long opslimit, size_t memlimit, int alg);
                // https://github.com/jedisct1/libsodium/blob/f6bd9140861ab6806f4a99923888b65477fc4e33/src/libsodium/include/sodium/crypto_pwhash.h
                crypto_pwhash(out.baseAddress!.assumingMemoryBound(to: UInt8.self), 32, p.baseAddress!.assumingMemoryBound(to: CChar.self), UInt64(p.count), s.baseAddress!.assumingMemoryBound(to: UInt8.self), parameters.operations, parameters.memory, parameters.algorithm)
            }}}
            guard status == 0 else { throw VaultError.crypto }
            return key
        } catch { key.destroy(); throw error }
    }
}
