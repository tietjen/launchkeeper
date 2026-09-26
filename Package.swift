// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "launchkeeper",
    platforms: [.macOS(.v14)],
    products: [
        // The core as a library: the SwiftUI app (tj/launchkeeper-app) builds on it.
        .library(name: "LaunchKeeperKit", targets: ["LaunchKeeperKit"]),
        .executable(name: "launchkeeper", targets: ["launchkeeper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.4.0")
    ],
    targets: [
        .target(name: "LaunchKeeperKit"),
        .executableTarget(
            name: "launchkeeper",
            dependencies: [
                "LaunchKeeperKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "LaunchKeeperKitTests",
            dependencies: ["LaunchKeeperKit"]
        ),
    ]
)
