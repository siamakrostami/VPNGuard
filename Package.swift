// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "VPNGuard",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "VPNGuard", targets: ["VPNGuardApp"]),
        .executable(name: "VPNGuardRun", targets: ["VPNGuardRunner"])
    ],
    targets: [
        .target(name: "VPNGuardCore"),
        .executableTarget(name: "VPNGuardApp", dependencies: ["VPNGuardCore"]),
        .executableTarget(name: "VPNGuardRunner", dependencies: ["VPNGuardCore"]),
        .testTarget(name: "VPNGuardCoreTests", dependencies: ["VPNGuardCore"])
    ],
    swiftLanguageModes: [.v6]
)
