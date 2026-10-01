// swift-tools-version: 6.0
// Neuralkit — connects a Mac to a supported EEG headset, imported as `Neuralkit`.
import PackageDescription

let package = Package(
    name: "Neuralkit",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "Neuralkit", targets: ["Neuralkit"]),
    ],
    targets: [
        .target(name: "Neuralkit"),
    ]
)
