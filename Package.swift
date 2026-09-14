// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "btmctl",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.4.0")
    ],
    targets: [
        .target(name: "BTMKit"),
        .executableTarget(
            name: "btmctl",
            dependencies: [
                "BTMKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "BTMKitTests",
            dependencies: ["BTMKit"]
        ),
    ]
)
