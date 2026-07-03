# tlsec

**Customizable handshake mTLS/TLS 1.3 library with kTLS support (NEED TESTS)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org/)

> **Status:** Almost done. Testing with OpenSSL.

`tlsec` is a pure Rust implementation of the TLS 1.3 protocol with a focus on flexibility, performance, and deep customization. It aims to give you full control over the handshake process, from the `ClientHello` to the final `Finished` message, while also supporting modern features like kernel TLS (kTLS).

## Features

*   **Pure Rust TLS 1.3:** Full implementation of the TLS 1.3 protocol (RFC 8446).
*   **Customizable Handshake:** Build and modify `ClientHello`, `ServerHello`, and extensions directly. Perfect for testing, fingerprinting, or implementing non-standard behaviors.
*   **High Performance:**
    *   **Zero-Copy Parsing:** Uses `bytes` and `BytesMut` to minimize unnecessary data copies.
    *   **Asynchronous I/O:** Built on `tokio` for scalable network applications.
    *   **kTLS Support:** Experimental support for offloading encryption to the kernel via `ktls`.
*   **mTLS (Mutual TLS):** Full support for client certificate authentication.
*   **Multiple Cipher Suites:** Support for `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`.
*   **Modern Cryptography:** Powered by `ring` for fast and secure cryptographic operations.

## Architecture & Design

`tlsec` is designed with a strong focus on transparency and control. The core state machine is built using a clear trait-based architecture, allowing you to follow each step of the handshake.

### Key Components

*   **`TlsConnection`:** The main entry point for a TLS connection.
*   **`MessageDeframer`:** Parses incoming TLS records from a byte stream.
*   **`RecordLayer`:** Handles encryption and decryption of TLS records.
*   **`State` Machine:** A `match`-based state machine (with a future `State<T>` trait refactor planned for improved type safety) that drives the handshake process.
*   **`MessageBuilder`:** Allows you to programmatically construct `ClientHello` and `ServerHello` messages.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tlsec = { git = "https://github.com/ecdhe-x25519/tlsec" }
