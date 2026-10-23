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

import XCTest

@_spi(Essentials) @_spi(ProtocolProvider) @testable import SwiftNetwork

#if IMPORT_CRYPTO && !NETWORK_NO_SWIFT_QUIC

/// Detecting stateless resets (RFC 9000 Section 10.3.1) in `QUICConnectionCore`.
@available(Network 0.1.0, *)
final class QUICConnectionCoreStatelessResetTests: XCTestCase {
    private static let token = QUICStatelessResetToken([UInt8](repeating: 0x5a, count: 16))!

    private static func connectedPair() -> LockstepPair {
        var serverConfiguration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        serverConfiguration.statelessResetToken = Self.token
        var pair = LockstepPair(serverConfiguration: serverConfiguration)
        pair.exchange()
        return pair
    }

    /// A short header, `padding` unpredictable bytes, and a token.
    private static func resetDatagram(
        padding: Int,
        token: QUICStatelessResetToken = QUICConnectionCoreStatelessResetTests.token
    ) -> [UInt8] {
        [0x41] + [UInt8](repeating: 0x9c, count: padding) + token.token
    }

    func testAStatelessResetEndsTheConnectionWithoutAReply() {
        var pair = Self.connectedPair()
        var datagram = Self.resetDatagram(padding: 20)
        var span = datagram.mutableSpan
        pair.client.receive(&span, now: pair.now)
        XCTAssertEqual(pair.client.closeReason, .statelessReset)
        XCTAssertTrue(pair.client.isTerminating)
        XCTAssertTrue(LockstepPair.drain(&pair.client, now: pair.now).isEmpty, "a reset connection sends nothing")
        for _ in 0..<3 {
            pair.advanceToNextDeadline()
        }
        XCTAssertTrue(LockstepPair.events(&pair.client).contains(.closed(.statelessReset)))
    }

    func testTheShortestStatelessResetIsDetected() {
        var pair = Self.connectedPair()
        var datagram = Self.resetDatagram(padding: 4)
        XCTAssertEqual(datagram.count, 21)
        var span = datagram.mutableSpan
        pair.client.receive(&span, now: pair.now)
        XCTAssertEqual(pair.client.closeReason, .statelessReset)
    }

    func testDatagramsThatAreNotAResetAreIgnored() {
        var pair = Self.connectedPair()
        let other = QUICStatelessResetToken([UInt8](repeating: 0x11, count: 16))!
        var long = Self.resetDatagram(padding: 20)
        long[0] = 0xc1
        for var datagram in [
            Self.resetDatagram(padding: 20, token: other),
            // Too short to be a reset.
            Self.resetDatagram(padding: 3),
            // A long header.
            long,
        ] {
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: pair.now)
        }
        XCTAssertNil(pair.client.closeReason)
        // The connection still works.
        pair.client.injectedFrames.append([0x01])
        pair.exchange()
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    /// Only the server's token counts: a client sends none.
    func testAServerKnowsNoTokenOfTheClient() {
        var pair = Self.connectedPair()
        guard var server = pair.server.take() else { return XCTFail("No server") }
        var datagram = Self.resetDatagram(padding: 20)
        var span = datagram.mutableSpan
        server.receive(&span, now: pair.now)
        XCTAssertNil(server.closeReason)
        pair.server = consume server
    }
}

#endif
