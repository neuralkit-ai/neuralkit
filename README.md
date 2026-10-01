# Neuralkit

Connects a Mac to a supported EEG headset (macOS 26). One product:

- `Neuralkit` — finding a headset, pairing it, and reading its data. This first release holds the package; the API follows.

```swift
// Package.swift
.package(url: "https://github.com/neuralkit-ai/neuralkit", from: "1.1.0"),
// …
.product(name: "Neuralkit", package: "neuralkit"),
```

## License

PolyForm Noncommercial 1.0.0 ([LICENSE.md](LICENSE.md)). Free for noncommercial use, and for government institutions. Commercial use by written agreement: [neuralkit.ai](https://neuralkit.ai). See [NOTICE](NOTICE).
