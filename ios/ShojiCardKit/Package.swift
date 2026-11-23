// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ShojiCardKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "ShojiCardKit", targets: ["ShojiCardKit"])],
    targets: [
        .target(name: "ShojiCardKit"),
        .testTarget(name: "ShojiCardKitTests", dependencies: ["ShojiCardKit"]),
    ]
)
