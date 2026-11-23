// swift-tools-version:5.9
import PackageDescription

// ShojiProverFFI.xcframework is not in the repository: build it with
// prover/scripts/build-apple.sh.
let package = Package(
    name: "ShojiProverKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "ShojiProverKit", targets: ["ShojiProverKit"])],
    targets: [
        .binaryTarget(name: "ShojiProverFFI", path: "ShojiProverFFI.xcframework"),
        .target(
            name: "ShojiProverKit",
            dependencies: ["ShojiProverFFI"],
            linkerSettings: [.linkedLibrary("c++")]),
        .testTarget(name: "ShojiProverKitTests", dependencies: ["ShojiProverKit"]),
    ]
)
