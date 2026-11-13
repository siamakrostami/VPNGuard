// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "VPNGuard",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "VPNGuard", targets: ["VPNGuardApp"]),
        .executable(name: "VPNGuardRun", targets: ["VPNGuardRunner"]),
        .executable(name: "VPNGuardProcessHost", targets: ["VPNGuardProcessHost"])
    ],
    targets: [
        .target(name: "CProcessLifecycle"),
        .executableTarget(name: "VPNGuardProcessHost", dependencies: ["CProcessLifecycle"]),
        .executableTarget(name: "VPNGuardProcessFixture"),
        .executableTarget(name: "VPNGuardSessionFixture", dependencies:["VPNGuardCore"]),
        .target(name: "CProxyTransport", linkerSettings: [.linkedLibrary("curl")]),
        .target(name: "VPNGuardCore", dependencies: ["CProxyTransport", "CProcessLifecycle"]),
        .executableTarget(name: "VPNGuardApp", dependencies: ["VPNGuardCore"]),
        .executableTarget(name: "VPNGuardRunner", dependencies: ["VPNGuardCore"]),
        .testTarget(name: "VPNGuardCoreTests", dependencies: ["VPNGuardCore", "CProcessLifecycle"])
    ],
    swiftLanguageModes: [.v6]
)
