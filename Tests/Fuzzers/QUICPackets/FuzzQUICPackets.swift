//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if !NETWORK_NO_SWIFT_QUIC

import Foundation
// `@testable` requires `-enable-testing`, which is only set under the Fuzzing trait.
#if Fuzzing
#if canImport(SwiftNetwork)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import SwiftNetwork
#elseif canImport(Network)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import Network
#endif
#endif

#if !Fuzzing
@main
struct RefuseToFuzz {
    static func main() {
        print("Refusing to fuzz.  Rebuild with Fuzzing trait.")
        exit(1)
    }
}
#else
#if os(Linux)
// On Linux SwiftPM renames an executable target's entry point to
// `<Module>_main` and links with `--defsym main=<Module>_main`, so the module
// can also be imported. Under the Fuzzing trait this file deliberately has no
// Swift entry point (libFuzzer's runtime supplies `main`), so that symbol does
// not exist and the link fails with:
//
//     ld.gold: error: undefined symbol 'FuzzQUICPackets_main' referenced in expression
//
// Supply it, and drive libFuzzer explicitly. `main` then resolves here via the
// `--defsym`, which also means libFuzzer's own `main` - a member of the static
// libclang_rt.fuzzer archive - is never extracted, so there is no duplicate
// `main`. macOS does not do this renaming, so it is left untouched.
@_silgen_name("LLVMFuzzerRunDriver")
private func LLVMFuzzerRunDriver(
    _ argc: UnsafeMutablePointer<Int32>,
    _ argv: UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?>,
    _ userCallback: @convention(c) (UnsafePointer<UInt8>?, Int) -> Int32
) -> Int32

@available(Network 0.1.0, *)
@_cdecl("FuzzQUICPackets_main")
func fuzzQUICPacketsMain(
    _ argc: Int32,
    _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    var argc = argc
    var argv = argv
    return withUnsafeMutablePointer(to: &argc) { argcPointer in
        withUnsafeMutablePointer(to: &argv) { argvPointer in
            LLVMFuzzerRunDriver(argcPointer, argvPointer) { start, count in
                guard let start else { return 0 }
                return fuzzPacketParser(start, count)
            }
        }
    }
}
#endif

/// A P-256 public key in DER, for the server the client would trust: without one, the
/// handshake doesn't start.
private let fuzzServerPublicKey: [UInt8] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xb6, 0x33, 0xa9, 0x2a, 0x5a, 0xce, 0xbb, 0x48, 0x1b,
    0xef, 0xd4, 0xc3, 0xf2, 0xda, 0x12, 0xf9, 0x50, 0xce, 0x36, 0xcb, 0x1d,
    0x1c, 0x79, 0x1f, 0xaf, 0x54, 0x7c, 0xf1, 0xf3, 0xcf, 0xe0, 0x8f, 0xf5,
    0x4a, 0xb8, 0x01, 0x30, 0x9e, 0x92, 0xb6, 0xb7, 0xec, 0x61, 0x41, 0xb7,
    0xcc, 0x8a, 0xef, 0xd6, 0x89, 0x90, 0xb6, 0x4b, 0xc2, 0x33, 0x8f, 0xbf,
    0x12, 0x86, 0x6b, 0xec, 0x02, 0x81, 0x28,
]

@available(Network 0.1.0, *)
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzPacketParser(_ start: UnsafePointer<UInt8>, _ count: Int) -> Int32 {
    guard count > 0 else {
        return 0
    }
    var start = start
    var count = count
    let cidLength = Int(start[0]) % (QUICConnectionID.maximumSize + 1)
    start += 1
    count -= 1

    guard count > cidLength else {
        return 0
    }

    // The bytes after the connection ID length are the connection ID that short header packets
    // are addressed to, then the datagram.
    var localConnectionID = QUICConnectionID(0)
    if cidLength != 0, let connectionID = QUICConnectionID(Array(UnsafeBufferPointer(start: start, count: cidLength))) {
        localConnectionID = connectionID
    }
    start += cidLength
    count -= cidLength

    let now = NetworkClock.Instant(milliseconds: 1_000)
    // The handshake has to start, or the connection closes before the datagram arrives.
    var tlsOptions = SwiftTLSProtocol.Options()
    tlsOptions.applicationProtocols = ["fuzz"]
    tlsOptions.serverName = "fuzz.local"
    tlsOptions.trustedRawPublicKeyCertificates = [fuzzServerPublicKey]
    var core = QUICConnectionCore(
        clientWith: QUICConnectionCore.Configuration(tlsOptions: tlsOptions),
        localConnectionID: localConnectionID,
        destinationConnectionID: QUICConnectionID(8),
        now: now
    )
    // The datagram is plaintext: null keys stand in for the keys of every packet number space,
    // and the connection acts as if the handshake completed, so 1-RTT packets get to frame
    // processing.
    core.prepareForFuzzing()

    var datagram = Array(UnsafeBufferPointer(start: start, count: count))
    var span = datagram.mutableSpan
    core.receive(&span, now: now)

    // Act on what the datagram did: the events, and the datagrams in response, such as the ACK
    // frame for whatever packet numbers arrived.
    while core.nextEvent() != nil {}
    var buffer = [UInt8](repeating: 0, count: 1500)
    for _ in 0..<16 {
        var output = buffer.mutableSpan
        guard core.send(into: &output, now: now) != nil else { break }
    }

    return 0
}
#endif
#endif
