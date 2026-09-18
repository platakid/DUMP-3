# Device acceptance checklist

These checks have NOT been executed. Use disposable sample media and a dedicated test installation.

## Build and automated tests

- Build the DUMP scheme in Xcode 16+ for simulator and a signed iPhone.
- Resolve the exact pinned package revision; inspect the packaged sodium version and verify target architecture support.
- Run Product → Test. All XCTest cases must pass, including export cleanup with a throwing destination substitute.
- Inspect the three KDF operations on the oldest intended device: verification, wrapping-key derivation, and passcode change. Confirm no out-of-memory failures and acceptable timing. Do not silently reduce parameters.

## Authentication and lifecycle

- Cold launch shows only the decoy lock. Wrong codes do not open Notes.
- `7002` opens Notes. Create/edit/delete notes, relaunch, and confirm persistence.
- Only a new note with exact trigger and a subsequent single Space opens the hidden landing. Confirm that the trigger draft was not persisted.
- Enter explicitly starts Gate 1. Face ID failure/cancellation never shows setup or Gate 2.
- Exercise device-passcode fallback, not just biometrics. With the strict no-exceptions inactive rule, a system prompt that deactivates the scene must cancel authentication. If this prevents completion, stop and obtain an explicit lifecycle-policy decision; do not exempt it silently.
- First setup requires matching input and the documented strength rule. Later use shows unlock, not setup.
- Background from every route, including mid-KDF, import, image decoding, playback, and export. Return to `7002`, re-enter the trigger, press Enter, and pass both gates again. Delayed completion must not unlock a revoked session.
- Change passcode, then verify all previously imported files still decrypt. The old passcode must fail.
- Test Keychain operations on a device without a passcode and in a dedicated disposable installation after device-passcode removal. There must be no fallback accessibility or automatic vault reset.
- Interrupt setup after saving the verifier but before storing the wrapped key. Only the same verified passcode, with no existing media, may complete setup.

## Media and exposure

- Import JPEG, HEIC, PNG, large panorama, H.264/HEVC MOV/MP4, Live Photo, and RAW/edited assets where available. Confirm all source resources must complete before offering original deletion.
- A cloud-only resource fails without downloading; no original is deleted.
- Compare original and decrypted bytes using the tests and controlled fixtures. Seek video near beginning/middle/end repeatedly. Check portrait orientation, image downsampling, unsupported codecs, and memory pressure.
- Corrupt a chunk, reorder chunks, truncate a file, append bytes, and swap resource filenames. All relevant reads must fail authentication or format validation.
- Inspect application-controlled filesystem writes during import and playback: vault bytes only in Application Support; no plaintext temp/cache media outside the explicitly approved export operation.
- Read backup exclusion and complete file-protection attributes on every committed and partial file. Verify persistence after rename and relaunch.
- Inspect app-switcher snapshots, Control Center interruptions, calls, notifications, recording already active at launch, recording beginning during playback, and AirPlay. The shield must cover modal presentations too.
- Take a screenshot from each visible route, including a presented preview/settings screen. Confirm the screenshot notification is visible in-app. Screenshot prevention is not promised.

## Photos deletion/export

- Confirm original deletion is optional and requires a separate tap after successful verification. Confirm Recently Deleted messaging and the native Photos deletion result.
- Export cannot be initiated from decoy/gates, a revoked session, or background code. Only Photos appears as a destination.
- Every export shows the exact protection warning plus the temporary-file limitations. Cancel makes no export; confirmation uses the current session without another passcode prompt.
- Check `isExcludedFromBackup`, complete file protection, and POSIX 0600 before any plaintext bytes are written.
- Check success, Photos denial/error, insufficient disk space, locked-device interruption, task cancellation before handoff, and file-write failure. Normal completion/error paths must start overwrite/delete immediately and report cleanup failures honestly.
- Export a large video while monitoring memory: plaintext app buffers should remain bounded by chunk size rather than video length.
- Confirm the vault ciphertext is unchanged after export. Deleting it must require a separate user action.
- Verify and document the approved failure case: force-killing during export may leave a plaintext temporary file. There is no physical secure-erasure guarantee or next-launch cleanup guarantee.

## Review before personal use

- Independently review the container format, nonce uniqueness, Keychain transaction handling, lifecycle races, protected-file errors, native media ownership, and export handoff/cleanup.
- Audit the final signed application and dependencies for logging, analytics, network calls, unintended entitlements, and sensitive diagnostic payloads. This source-only handoff is not an independent security audit.
