# DUMP

iPhone-only SwiftUI source project, targeting iOS 17 or later. Native UIKit is used for precise note input, privacy covers, and image/video rendering. No server, account, telemetry, widget, share extension, or cloud entitlement is included.

**Status:** source implementation with an Xcode project and XCTest suite. This was prepared on Windows: no iOS SDK/Xcode build, XCTest execution, simulator run, or physical-device verification has been performed. Treat it as an unaudited implementation for review and device testing, not a certified secure vault.

## Open and run

**Building without a Mac:** see [CODEMAGIC.md](CODEMAGIC.md). Start with the unsigned simulator build/test workflow; an installable iPhone IPA additionally requires Apple signing credentials.

1. Copy this folder to a Mac with Xcode 16 or later.
2. Open `DUMP.xcodeproj`. Allow Swift Package Manager to resolve the pinned sodium dependency.
3. Select the DUMP target, set a unique bundle identifier and your signing team, and select an iPhone. The iPhone must have a device passcode.
4. Run the app. Choose Product → Test to run the DUMP scheme's tests.
5. Complete `DEVICE-VALIDATION.md` before entrusting personal media to the app.

The package is pinned to swift-sodium revision `cfd195c76882aa9b997560ca7cb95d72fbf5db00`. Its `Clibsodium` product supplies the native sodium bindings; application code imports `_Clibsodium`, the package's exported shim. The high-level password wrapper is not used: direct calls allow explicit buffer ownership, full unsigned UTF-8 support, and the exact required `crypto_pwhash_str` / `crypto_pwhash_str_verify` split.

## Flow

```text
Launch / inactive / background / screen capture
    → 7002 decoy lock
    → functional Note Dump
    → new blank note: DUMPunlock0715, followed by a single Space insertion
    → animated hidden landing screen, containing DUMP and Enter only
    → Enter
    → Gate 1: deviceOwnerAuthentication (biometrics or device passcode)
    → first use: create and confirm a vault passcode
      later use: Gate 2, verify existing vault passcode
    → vault
```

The decoy code and trigger are intentionally discoverable constants in the binary. They provide concealment, not cryptographic security. Neither bypasses the two vault gates. Existing notes, a full pasted trigger including its trailing space, extra text, and a newline do not trigger the transition. The trigger draft is cleared without being saved. Notes use separate local storage and do not contain vault data.

Every inactive/background event revokes the session. Old callbacks cannot reopen it. **There is no exemption for authentication or system permission prompts.** If a device's system prompt makes the scene inactive, the attempt is cancelled and the user returns to the decoy lock. Verify this on the intended iPhone/OS; if it prevents Gate 1 from completing, the strict inactive rule needs an explicit product decision, not a hidden bypass.

## Passcode and key handling

The exact validation rule is: at least eight Swift `Character` values, at least one Unicode scalar in `CharacterSet.decimalDigits`, `.symbols`, or `.punctuationCharacters`, at most 1,024 UTF-8 bytes, and no null scalar. Whitespace alone does not satisfy the number/symbol requirement. No case folding, trimming, or Unicode normalization is applied. Both the UI coordinator and credential service enforce validation on creation/change.

* Verification hash: `crypto_pwhash_str`, Argon2id, 3 passes, 64 MiB. The pinned library's output must start with `$argon2id$`.
* All verification, including setup confirmation and current/new passcode checks during a change: **only `crypto_pwhash_str_verify`**. Vault passwords are never compared as plaintext strings.
* Wrapping key: a separate `crypto_pwhash` Argon2id v1.3 operation, 32-byte output, independently random 16-byte salt, 3 passes, 64 MiB. Parameters are recorded and unexpected parameters rejected. Benchmark on the oldest supported iPhone; do not silently weaken them on allocation failure.
* Vault master key: `SymmetricKey(size: .bits256)`. The first verifier record is saved before this key is generated.
* The master key is AES-GCM wrapped with the derived wrapping key. It is never stored unwrapped at rest. Unwrapping occurs in memory only after Gate 2 verification succeeds in a session that passed Gate 1.
* A passcode change verifies the current passcode, unwraps the existing key, creates a new verifier and independent wrapping salt, then atomically updates one Keychain item. It does not generate another master key.
* There is no reset, forgotten-passcode bypass, or data-wipe feature. Missing credentials with surviving media fail closed. An interrupted first setup with a saved verifier but no wrapped key can complete only after that passcode verifies and only if no media exists.

The exact Keychain addition dictionary, as constructed in `KeychainStore.swift`, is:

```swift
[
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "local.dump.key-record.v1",
    kSecAttrAccount as String: "vault",
    kSecAttrSynchronizable as String: false,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    kSecValueData as String: try JSONEncoder().encode(record)
]
```

`record` contains version, Argon2id verifier, wrapping salt/parameters, and the **wrapped** key. A single-item `SecItemUpdate` prevents mismatched verifier/key versions during passcode change. Keychain failures never fall back to weaker accessibility. Removing the device passcode destroys this class of Keychain item, making surviving media unrecoverable.

## Media storage and display

`MediaStore.swift` defines a versioned AES-GCM chunk container. Each imported resource receives a fresh AES-256 resource key. All media uses the same scheme, including small photos. No custom cipher, hash, or key derivation primitive is implemented.

* 4,096-byte header: magic/version, sealed-header length, a master-key-encrypted resource key plus metadata, then padding.
* Fixed 1 MiB plaintext chunks; the last may be shorter. Each stores CryptoKit's combined nonce/ciphertext/tag representation.
* Per-resource counter nonce: four zero bytes followed by a big-endian 64-bit chunk index. Every resource gets a new key; failed writes are not resumed with the same key/counter.
* Authenticated data binds format version, resource UUID, chunk index, and plaintext chunk length. Encrypted metadata binds resource UUID and total byte count. A reader checks exact physical file length, so truncation and trailing data are rejected.
* Header seals and master-key wraps use CryptoKit-generated random nonces. The fixed-size/version parser bounds resource length to 1 TiB and header length to its reserved space.
* Every chunk is read back from the destination, decrypted, and compared byte-for-byte with its source buffer. The complete container is authenticated again before commit and original-deletion eligibility.

Ciphertext is written under Application Support/DUMP/Media. Incomplete `.partial` files stay encrypted and are not listed as media. Every directory/file is backup-excluded and uses complete file protection. Exclusion is applied to an empty file **before content is written** and reapplied after the final rename. The protection helper contains:

```swift
var values = URLResourceValues()
values.isExcludedFromBackup = true
try target.setResourceValues(values)
```

The app does not claim a global switch to disable iOS backups. It explicitly excludes its managed content and disables file sharing.

PhotoKit's streaming resource API is used for imports with network access disabled. All resources of an asset are imported, including Live Photo companion video and adjustment data. Failure of any resource prevents original deletion. Supporting resources remain encrypted but are not independently viewable/exportable as photos. Live Photo components are displayed/exported individually; this build does not reconstruct a Live Photo asset on export.

Images use an in-memory, random-access `CGDataProvider` with bounded decrypted read buffers and ImageIO downsampling to at most 2,560 pixels. Videos use an `AVAssetResourceLoaderDelegate` over a custom local URL scheme. No plaintext playback file, app thumbnail cache, or system-indexed thumbnail is created. External playback is disabled. Framework/decoder allocations and internal OS behavior are outside the application's direct control.

## Photos deletion and export

Original deletion is optional, requires its own confirmation, and is offered only after every imported resource verifies. The UI says that Photos moves originals to Recently Deleted for up to 30 days, identifies this as an iOS platform limitation, and makes no secure-erasure promise. Photos library deletion may synchronize through the user's iCloud Photos settings.

Export is **Photos only**, through a leading swipe or context menu on an image/video. It requires the active, foreground two-gate session and an explicit warning-screen confirmation. Per your decision, there is no additional Gate 2 prompt. The exact warning is:

> Exporting removes this file's protection. Once saved outside DUMP, it is no longer encrypted and is subject to normal iOS storage/backup behavior.

The encrypted vault item is never deleted by export. Deleting a vault item remains a separate confirmation.

Your approved export exception permits one tracked plaintext file in `NSTemporaryDirectory()` to avoid loading a large video into RAM. It is created exclusively with `O_NOFOLLOW` and 0600 permissions; backup exclusion and complete file protection are applied while it is still empty. It is filled from bounded decrypted chunks, passed to `PHAssetCreationRequest.addResource(with:fileURL:options:)`, and an overwrite-then-delete attempt begins immediately after the Photos operation completes or throws. A `defer` covers normal exits; deletion is still attempted if overwriting fails. Cleanup failure is reported after authentication, without logging paths or content. No next-launch cleanup fallback is implemented.

**Approved limits:** flash/APFS overwriting does not guarantee physical secure erasure; force termination, power loss, or suspension may prevent timely cleanup. A temporary file can remain after termination. Once Photos accepts a request, iOS controls that request; a later app lock cannot retract an already submitted export. Photos may sync the exported copy outside this device. These limitations also appear in the export confirmation UI.

## Memory and screen protection

Owned secret buffers are explicitly overwritten using `sodium_memzero`. Sessions register password, master-key, wrapping-key, and resource-key buffers for revocation. Background/inactive handling installs a native opaque shield, clears rendered content and authentication state, cancels active imports/authentication, and destroys registered buffers. A currently executing native cryptographic operation must return before its borrowed buffer can be safely wiped; work cannot be forcefully interrupted mid-call.

Swift strings, CryptoKit internal copies, decoder surfaces, and memory retained by system APIs cannot be comprehensively zeroed by application code. AVFoundation explicitly requires response data to remain valid after handoff. Its owned response allocation is wiped when AVFoundation releases it; playback is stopped and the player/loader released on lock. This is **not** a promise of instantaneous erasure of every process/system copy.

Screenshot notification occurs after the screenshot; it alerts the user and cannot undo the capture. Active recording/mirroring hides content and locks the session. Native scene/app lifecycle notifications install an opaque app-switcher cover before session cleanup. Capture detection cannot retroactively remove already captured frames.

## Validation

The included tests cover Gate 1 failure, late callbacks after lock, full re-authentication after background, the hidden trigger, passcode validation, wrong-password rejection, key preservation across passcode changes, buffer revocation, multi-chunk byte-identical round trips, random-access boundary reads, backup exclusion including incomplete files, tamper/reorder/truncation rejection, and export cleanup on both success and a thrown destination error.

Locally completed: Xcode project structural parse and source-reference checks; Swift grammar parse (15 source files, no syntax errors). These do **not** type-check framework calls or prove runtime correctness. XCTest, signing, actual compilation, device behavior, real Keychain attributes, playback formats, Photos permissions/transactions, and independent security review remain required. See `DEVICE-VALIDATION.md` and `SOURCES.md`.
