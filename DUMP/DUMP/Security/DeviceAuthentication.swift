import Foundation
import LocalAuthentication

@MainActor
protocol DeviceAuthenticating: AnyObject {

    func authenticate() async throws -> Bool

    func cancel()
}


// MARK: - Device Authentication

@MainActor
final class DeviceAuthentication: DeviceAuthenticating {

    private var context: LAContext?


    func authenticate() async throws -> Bool {

        /*
         Invalidate any previous authentication operation before
         creating a new Gate 1 request.
        */

        cancel()

        let current = LAContext()

        /*
         Prevent Touch ID authentication from being automatically
         reused from a recent successful authentication.
        */

        current.touchIDAuthenticationAllowableReuseDuration = 0

        /*
         Explicit system authentication cancel button.
        */

        current.localizedCancelTitle = "Cancel"

        /*
         We intentionally do NOT configure a passcode fallback.

         Gate 1 is biometric-only.

         The vault password remains the independent cryptographic
         Gate 2 and is never replaced by biometric authentication.
        */

        current.localizedFallbackTitle = ""

        context = current

        defer {

            if context === current {
                context = nil
            }
        }


        // MARK: Check availability

        var error: NSError?

        /*
         deviceOwnerAuthenticationWithBiometrics means:

         Face ID / Touch ID only.

         The device passcode does NOT satisfy this Gate 1 request.

         This is deliberately different from:

             .deviceOwnerAuthentication

         which allows iOS to use the device passcode as a fallback.
        */

        guard current.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        ) else {

            /*
             Fail closed.

             We do not downgrade automatically to the device passcode
             when biometric authentication is unavailable.
            */

            if let error {
                throw error
            }

            throw VaultError.locked
        }


        // MARK: Authenticate

        let success = try await current.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason:
                "Authenticate to continue."
        )

        /*
         evaluatePolicy normally throws on failure, but explicitly
         require a true result anyway.
        */

        guard success else {
            throw VaultError.locked
        }

        /*
         AppModel performs its own generation/session checks after
         this returns, protecting against a successful authentication
         callback arriving after lock().
        */

        return true
    }


    // MARK: Cancel

    func cancel() {

        /*
         invalidate() causes an outstanding LocalAuthentication
         evaluation to fail.

         AppModel's generation checks remain the authoritative
         protection against stale asynchronous results.
        */

        context?.invalidate()

        context = nil
    }
}
