import ShojiCardKit
import SwiftUI

@main
struct ShojiProbeApp: App {
    @State private var link: VerificationLink?
    @State private var linkError = false

    var body: some Scene {
        WindowGroup {
            VerifyView(link: $link)
                // Opened from a service's QR code: shoji://verify?u=<origin>&s=<session>
                .onOpenURL { url in
                    if let parsed = try? VerificationLink(url) {
                        link = parsed
                    } else {
                        linkError = true
                    }
                }
                .task {
                    // Development aid: `-shoji-link <url>` on the command line behaves like
                    // opening that link (the simulator cannot scan a QR code).
                    let args = CommandLine.arguments
                    if let i = args.firstIndex(of: "-shoji-link"), i + 1 < args.count, let url = URL(string: args[i + 1]) {
                        link = try? VerificationLink(url)
                    }
                }
                .alert("この QR コードには対応していません", isPresented: $linkError) {
                    Button("OK", role: .cancel) {}
                }
        }
    }
}
