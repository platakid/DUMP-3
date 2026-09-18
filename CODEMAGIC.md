# Build DUMP with Codemagic

## First build: no Apple signing credentials needed

1. Connect this GitHub repository to Codemagic and select branch `main`.
2. Use the repository's root `codemagic.yaml` configuration.
3. Start **DUMP - Build and test (no signing needed)** (`dump-ios-check`).
4. Wait for dependency resolution, compilation and all 15 XCTest cases to pass.

This produces test results, build logs and `DUMP-simulator.zip`. The ZIP runs only in an iOS simulator on a Mac; it cannot be installed on an iPhone. The workflow chooses an available iPhone simulator running iOS 17 or later. There are no automatic build triggers or publishing steps.

## Install on your iPhone

The separate **DUMP - Signed iPhone app (Apple credentials required)** workflow requires an Apple Developer account and these credentials uploaded in Codemagic's code-signing settings:

- An Apple Development signing certificate with its private key (.p12).
- An iOS development provisioning profile for `local.dump.app`, including your registered iPhone and that certificate.

If you use a different bundle identifier, update both app configurations in `DUMP.xcodeproj/project.pbxproj` and `bundle_identifier` in `codemagic.yaml`, and obtain the matching profile. Never commit signing credentials to GitHub.

Select `dump-ios-development` after the simulator workflow passes. It runs tests, applies the uploaded profile and produces an IPA in the build artifacts. It does not publish to the App Store or TestFlight.

## Validation limits

The project was prepared on Windows. Static checks do not replace the first real Xcode build. Complete `DEVICE-VALIDATION.md` on an iPhone after compilation succeeds, particularly authentication prompts, relocking, Photos permissions, video playback and export cleanup. A green simulator build is not a security audit.

Official setup references: [native iOS builds](https://docs.codemagic.io/yaml-quick-start/building-a-native-ios-app/) and [iOS signing](https://docs.codemagic.io/yaml-code-signing/signing-ios/).
