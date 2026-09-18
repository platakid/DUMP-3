# Validation results — 2026-09-17

| Check | Result |
| --- | --- |
| Swift grammar parsing | 15 files parsed with zero syntax errors using tree-sitter-swift under a checksum-verified Node 22 runtime. Grammar parsing is not Swift type checking. |
| Xcode project structure | Parsed successfully; all 15 Swift source references resolve. |
| Shared scheme and Info.plist | Both parse as XML. |
| Source scan | The only application temporary-directory reference is the explicitly approved Photos export implementation. No application `URLSession`, `print`, or `NSLog` calls were found. This is not a binary/dependency audit. |
| Automated tests supplied | 15 XCTest cases across SecurityTests and MediaStoreTests. |
| XCTest execution | **Not run**: this environment is Windows and has no Xcode/iOS SDK. |
| Xcode compilation / Swift type checking | **Not run**. |
| iPhone / simulator / UI validation | **Not run**. |
| Independent security review | **Not performed**. |

The first syntax-parser runtime (Node 24 with the older WASM grammar) reported zero syntax errors but crashed during teardown. The check was repeated with Node 22 and completed successfully. This tooling issue was not treated as an application test pass.

The highest-priority device question is the strict inactive rule during system authentication and permissions. The code intentionally locks on every inactive event, with no authentication-prompt exemption. If a required system prompt deactivates the scene, the flow can be cancelled; this must be tested and resolved explicitly before release.

See DEVICE-VALIDATION.md for the remaining acceptance work. No actual media, credentials, Keychain items, or Photos library were accessed during development.
