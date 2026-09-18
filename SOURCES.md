# Source and documentation review

Reviewed on 2026-09-17. The sodium repositories were cloned and the actual source/header files read before their integrations were written. Apple frameworks are supplied by the iOS SDK; their implementation is not distributed as a cloneable public iOS repository. Their official documentation/declarations were retrieved and read, rather than substituting a different framework.

## Pinned source

- [swift-sodium package and exported C binding](https://github.com/jedisct1/swift-sodium/tree/cfd195c76882aa9b997560ca7cb95d72fbf5db00): `Package.swift`, `Sources/_Clibsodium/Clibsodium.swift`, `Sources/Sodium/PWHash.swift`, and bundled password-hashing/version headers. The bundled version header reports sodium 1.0.22.
- [libsodium source](https://github.com/jedisct1/libsodium/tree/f6bd9140861ab6806f4a99923888b65477fc4e33): `src/libsodium/crypto_pwhash/crypto_pwhash.c`, `include/sodium/crypto_pwhash.h`, `crypto_pwhash_argon2id.h`, `core.h`, `utils.h`, and `randombytes.h`.
- [Password hashing and verification](https://libsodium.gitbook.io/doc/password_hashing/default_phf): salts, output formats, verification, parameters, and Argon2id algorithm selection.
- [Secretstream documentation](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream): reviewed as the alternative; not used. The implementation consistently uses AES-GCM.

## Apple declarations and contracts

- [SymmetricKey generation](https://developer.apple.com/documentation/cryptokit/symmetrickey/init(size:)) and [construction from bytes](https://developer.apple.com/documentation/cryptokit/symmetrickey/init(data:)).
- [ContiguousBytes access](https://developer.apple.com/documentation/foundation/contiguousbytes/withunsafebytes(_:)).
- [AES-GCM seal](https://developer.apple.com/documentation/cryptokit/aes/gcm/seal(_:using:nonce:authenticating:)), [open](https://developer.apple.com/documentation/cryptokit/aes/gcm/open(_:using:authenticating:)), [nonce](https://developer.apple.com/documentation/cryptokit/aes/gcm/nonce/init(data:)), and [combined sealed box](https://developer.apple.com/documentation/cryptokit/aes/gcm/sealedbox/init(combined:)).
- [LAContext policy evaluation](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)) and [context invalidation](https://developer.apple.com/documentation/localauthentication/lacontext/invalidate()).
- [SecItemAdd](https://developer.apple.com/documentation/security/secitemadd(_:_:)), [SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)), and [SecItemUpdate](https://developer.apple.com/documentation/security/secitemupdate(_:_:)).
- [WhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) and [Keychain synchronization](https://developer.apple.com/documentation/security/ksecattrsynchronizable).
- [Backup exclusion](https://developer.apple.com/documentation/foundation/urlresourcevalues/isexcludedfrombackup).
- [Streaming Photos resource requests](https://developer.apple.com/documentation/photos/phassetresourcemanager/requestdata(for:options:datareceivedhandler:completionhandler:)).
- [Photos resource creation with a file URL](https://developer.apple.com/documentation/photos/phassetcreationrequest/addresource(with:fileurl:options:)) and [with Data](https://developer.apple.com/documentation/photos/phassetcreationrequest/addresource(with:data:options:)).
- [CGDataProvider direct callbacks](https://developer.apple.com/documentation/coregraphics/cgdataproviderdirectcallbacks) and [ImageIO data-provider source](https://developer.apple.com/documentation/imageio/cgimagesourcecreatewithdataprovider(_:_:)).
- [AVFoundation response ownership](https://developer.apple.com/documentation/avfoundation/avassetresourceloadingdatarequest/respond(with:)): the framework can retain the supplied data beyond the return from `respond`.
- [Screen capture status](https://developer.apple.com/documentation/uikit/uiscreen/iscaptured) and [will-resign-active notification](https://developer.apple.com/documentation/uikit/uiapplication/willresignactivenotification).

Exact external cryptographic/authentication function signatures and source links are placed immediately above their calls in the security files. Application helper calls are centralized around those annotated integration points.
