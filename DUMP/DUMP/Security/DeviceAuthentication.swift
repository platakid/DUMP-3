import Foundation
import LocalAuthentication

@MainActor
protocol DeviceAuthenticating: AnyObject {

    func authenticate() async throws -> Bool

    func cancel()
}

@MainActor
final class DeviceAuthentication:
    DeviceAuthenticating {

    private var context: LAContext?

    func authenticate() async throws -> Bool {

        /*
         Invalidate any genuinely old authentication context before
         beginning a new Gate 1 request.
         */
        cancel()

        let current = LAContext()

        /*
         Don't allow Touch ID reuse from an earlier authentication.

         This property affects Touch ID; Face ID authentication is
         still handled normally by LocalAuthentication.
         */
        current.touchIDAuthenticationAllowableReuseDuration = 0

        /*
         Give iOS an explicit cancel-button label.
         */
        current.localizedCancelTitle = "Cancel"

        context = current

        defer {

            if context === current {
                context = nil
            }
        }

        /*
         deviceOwnerAuthentication allows the normal iOS
         authentication flow.

         On Face ID devices, Face ID is presented first.
         iOS may provide the device-passcode fallback according to
         system authentication policy.

         Most importantly, PrivacyDelegate no longer invalidates this
         LAContext merely because the system authentication UI caused
         the app to temporarily resign active.
         */
        return try await current.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason:
                "Authenticate to continue."
        )
    }

    func cancel() {

        context?.invalidate()

        context = nil
    }
}
