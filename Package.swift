// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "launchkeeper",
    platforms: [.macOS(.v14)],
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
