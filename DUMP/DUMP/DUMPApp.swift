import SwiftUI

@main
@MainActor
struct DUMPApp: App {

    @UIApplicationDelegateAdaptor(PrivacyDelegate.self)
    private var delegate

    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .onAppear {
                    delegate.model = model
                    delegate.refreshCapture()
                }
        }
    }
}

@MainActor
final class PrivacyDelegate: NSObject, UIApplicationDelegate {

    weak var model: AppModel?

    private var observers: [NSObjectProtocol] = []
    private let shieldTag = 70020715

    // MARK: - Launch

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions:
            [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {

        /*
         TEMPORARILY INACTIVE

         Face ID and other system interfaces can cause the scene
         to temporarily deactivate.

         We protect what is visible with the privacy shield,
         but DO NOT destroy the authentication session.
         */
        observers.append(
            NotificationCenter.default.addObserver(
                forName: UIScene.willDeactivateNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in

                MainActor.assumeIsolated {
                    self?.cover()
                }
            }
        )

        /*
         ACTUAL BACKGROUND

         This is a genuine security transition.

         Now we:
         - cover the UI
         - invalidate the session
         - cancel authentication
         - revoke the lease
         - return to the decoy lock
         */
        observers.append(
            NotificationCenter.default.addObserver(
                forName: UIScene.didEnterBackgroundNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in

                MainActor.assumeIsolated {
                    self?.cover()
                    self?.model?.lock()
                }
            }
        )

        /*
         SCENE ACTIVE AGAIN

         Face ID can cause temporary scene inactivity.

         When the scene becomes active again, remove the privacy
         shield immediately unless screen capture is active.

         IMPORTANT:
         We deliberately do NOT check
         UIApplication.shared.applicationState here before uncovering.
         UIScene.didActivateNotification already tells us that this
         scene has become active.
         */
        observers.append(
            NotificationCenter.default.addObserver(
                forName: UIScene.didActivateNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in

                MainActor.assumeIsolated {
                    self?.sceneDidActivate()
                }
            }
        )

        // Screen recording / mirroring state changed.
        observers.append(
            NotificationCenter.default.addObserver(
                forName: UIScreen.capturedDidChangeNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in

                MainActor.assumeIsolated {
                    self?.refreshCapture()
                }
            }
        )

        // Screenshot warning.
        observers.append(
            NotificationCenter.default.addObserver(
                forName: UIApplication.userDidTakeScreenshotNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in

                MainActor.assumeIsolated {
                    self?.showScreenshotNotice()
                }
            }
        )

        return true
    }

    // MARK: - Windows

    private var windows: [UIWindow] {

        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
    }

    // MARK: - Privacy Shield

    private func cover() {

        for window in windows
        where window.viewWithTag(shieldTag) == nil {

            let shield = UIView(
                frame: window.bounds
            )

            shield.tag = shieldTag

            shield.backgroundColor =
                .systemBackground

            shield.autoresizingMask = [
                .flexibleWidth,
                .flexibleHeight
            ]

            shield.isUserInteractionEnabled = true

            let label = UILabel()

            label.text = "DUMP"

            label.font = .systemFont(
                ofSize: 28,
                weight: .semibold
            )

            label.translatesAutoresizingMaskIntoConstraints =
                false

            shield.addSubview(label)

            NSLayoutConstraint.activate([

                label.centerXAnchor.constraint(
                    equalTo:
                        shield.centerXAnchor
                ),

                label.centerYAnchor.constraint(
                    equalTo:
                        shield.centerYAnchor
                )
            ])

            window.addSubview(shield)
        }

        CATransaction.flush()
    }

    private func uncover() {

        windows.forEach {

            $0.viewWithTag(shieldTag)?
                .removeFromSuperview()
        }
    }

    // MARK: - Scene Activation

    private func sceneDidActivate() {

        /*
         If the screen is actively being captured,
         never reveal DUMP.
         */
        if UIScreen.screens.contains(
            where: \.isCaptured
        ) {

            cover()

            model?.lock()

        } else {

            /*
             The scene has explicitly reported that it is active.

             Remove the native privacy shield immediately.

             This is especially important after Face ID succeeds:
             the SwiftUI interface underneath may already have moved
             from Gate 1 to Setup/Gate 2.
             */
            uncover()
        }
    }

    // MARK: - Screen Capture

    func refreshCapture() {

        if UIScreen.screens.contains(
            where: \.isCaptured
        ) {

            cover()

            model?.lock()

            return
        }

        /*
         This method can also be called from onAppear, where checking
         the application state is appropriate.
         */
        if UIApplication.shared.applicationState == .active {

            uncover()
        }
    }

    // MARK: - Screenshot Notice

    private func showScreenshotNotice() {

        guard
            UIApplication.shared.applicationState == .active,

            !UIScreen.screens.contains(
                where: \.isCaptured
            ),

            let window =
                windows.first(
                    where: \.isKeyWindow
                )

        else {
            return
        }

        let notice = UILabel()

        notice.text =
            "Screenshot detected. iOS has already captured this screen."

        notice.numberOfLines = 0

        notice.textAlignment =
            .center

        notice.font =
            .preferredFont(
                forTextStyle: .footnote
            )

        notice.backgroundColor =
            .secondarySystemBackground

        notice.layer.cornerRadius = 14

        notice.clipsToBounds = true

        notice.translatesAutoresizingMaskIntoConstraints =
            false

        window.addSubview(notice)

        NSLayoutConstraint.activate([

            notice.leadingAnchor.constraint(
                equalTo:
                    window.safeAreaLayoutGuide.leadingAnchor,
                constant: 16
            ),

            notice.trailingAnchor.constraint(
                equalTo:
                    window.safeAreaLayoutGuide.trailingAnchor,
                constant: -16
            ),

            notice.topAnchor.constraint(
                equalTo:
                    window.safeAreaLayoutGuide.topAnchor,
                constant: 8
            ),

            notice.heightAnchor.constraint(
                greaterThanOrEqualToConstant: 64
            )
        ])

        UIAccessibility.post(
            notification: .announcement,
            argument: notice.text
        )

        DispatchQueue.main.asyncAfter(
            deadline: .now() + 6
        ) {

            notice.removeFromSuperview()
        }
    }

    // MARK: - UIApplication Lifecycle

    func applicationWillResignActive(
        _ application: UIApplication
    ) {

        /*
         DO NOT call model.lock() here.

         Face ID can temporarily make the application inactive.

         We only hide the contents.
         */
        cover()
    }

    func applicationDidEnterBackground(
        _ application: UIApplication
    ) {

        /*
         Genuine background transition.

         This is where the security session must be destroyed.
         */
        cover()

        model?.lock()
    }

    func applicationDidBecomeActive(
        _ application: UIApplication
    ) {

        /*
         The application is active again.

         Remove the shield unless screen capture is active.
         */
        sceneDidActivate()
    }
}
