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

/// Keepalives and the idle timer in `QUICConnectionCore`.
@available(Network 0.1.0, *)
final class QUICConnectionCoreKeepAliveTests: XCTestCase {
    private static func configuration(
        idleTimeout: NetworkDuration,
        keepAlive: NetworkDuration? = nil,
        maxUnacknowledgedKeepAlives: Int = 0
    ) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.maxIdleTimeout = idleTimeout
        configuration.keepAliveInterval = keepAlive
        configuration.maxUnacknowledgedKeepAlives = maxUnacknowledgedKeepAlives
        return configuration
    }

    /// Runs the timers for `duration`, delivering everything, unless `drop` loses it.
    private static func idle(
        _ pair: inout LockstepPair,
        for duration: NetworkDuration,
        drop: (_ toServer: Bool, _ index: Int) -> Bool = { _, _ in false }
    ) {
        let end = pair.now.advanced(by: duration)
        for _ in 0..<1000 {
            pair.advanceToNextDeadline()
            pair.exchange(drop: drop)
            if pair.now >= end || (pair.client.isClosed && pair.server?.isClosed != false) { break }
        }
    }

    func testKeepAlivesKeepAnIdleConnectionOpen() {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(idleTimeout: .seconds(3), keepAlive: .seconds(1)),
            serverConfiguration: Self.configuration(idleTimeout: .seconds(3))
        )
        pair.exchange()
        Self.idle(&pair, for: .seconds(60))
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
        // The last one may still wait for its acknowledgement.
        XCTAssertLessThanOrEqual(pair.client.unacknowledgedKeepAlives, 1, "the keepalives are acknowledged")
    }

    func testAKeepAliveIntervalAtOrAboveTheIdleTimeoutHasNoEffect() {
        for keepAlive in [NetworkDuration.seconds(3), .seconds(5)] {
            var pair = LockstepPair(
                clientConfiguration: Self.configuration(idleTimeout: .seconds(3), keepAlive: keepAlive),
                serverConfiguration: Self.configuration(idleTimeout: .seconds(3))
            )
            pair.exchange()
            XCTAssertNil(pair.client.keepAliveDeadline)
            Self.idle(&pair, for: .seconds(60))
            XCTAssertEqual(pair.client.closeReason, .idleTimeout, "keepalive \(keepAlive)")
        }
    }

    func testTheSmallerIdleTimeoutOfThePeerCountsForTheKeepAlive() {
        // Our idle timeout allows the interval, the peer's doesn't.
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(idleTimeout: .seconds(30), keepAlive: .seconds(5)),
            serverConfiguration: Self.configuration(idleTimeout: .seconds(3))
        )
        pair.exchange()
        XCTAssertNil(pair.client.keepAliveDeadline)
    }

    func testUnacknowledgedKeepAlivesCloseTheConnection() {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(
                idleTimeout: .seconds(100),
                keepAlive: .seconds(1),
                maxUnacknowledgedKeepAlives: 2
            ),
            serverConfiguration: Self.configuration(idleTimeout: .seconds(100))
        )
        pair.exchange()
        let start = pair.now
        // The server never hears from the client again.
        for _ in 0..<100 where pair.client.closeReason == nil {
            pair.advanceToNextDeadline()
            pair.exchange(drop: { toServer, _ in toServer })
        }
        XCTAssertEqual(pair.client.closeReason, .keepAliveTimeout)
        // Two keepalives went out a second apart, after the server's last retransmission
        // arrived; the third timer closes.
        XCTAssertLessThan(start.duration(to: pair.now), .seconds(10))
    }

    func testKeepAlivesCanBeStartedAndStopped() {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(idleTimeout: .seconds(30)),
            serverConfiguration: Self.configuration(idleTimeout: .seconds(30))
        )
        pair.exchange()
        XCTAssertNil(pair.client.keepAliveDeadline)
        pair.client.setKeepAliveInterval(.seconds(2), now: pair.now)
        XCTAssertEqual(pair.client.keepAliveDeadline, pair.now.advanced(by: .seconds(2)))
        Self.idle(&pair, for: .seconds(100))
        XCTAssertNil(pair.client.closeReason)
        pair.client.setKeepAliveInterval(nil, now: pair.now)
        XCTAssertNil(pair.client.keepAliveDeadline)
        Self.idle(&pair, for: .seconds(100))
        XCTAssertEqual(pair.client.closeReason, .idleTimeout)
    }

    /// RFC 9000 Section 10.1: sending the first ack-eliciting packet since the last one arrived
    /// restarts the idle timer; sending more doesn't.
    func testTheFirstAckElicitingPacketSinceAReceiveRestartsTheIdleTimer() throws {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(idleTimeout: .seconds(3)),
            serverConfiguration: Self.configuration(idleTimeout: .seconds(3))
        )
        pair.exchange()
        let received = pair.now
        XCTAssertEqual(pair.client.idleDeadline, received.advanced(by: .seconds(3)))
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.now = received.advanced(by: .seconds(2))
        pair.client.write([UInt8]([1]).span.bytes, to: streamID)
        XCTAssertFalse(LockstepPair.drain(&pair.client, now: pair.now).isEmpty)
        XCTAssertEqual(pair.client.idleDeadline, received.advanced(by: .seconds(5)))
        pair.now = received.advanced(by: .milliseconds(2500))
        pair.client.write([UInt8]([2]).span.bytes, to: streamID)
        XCTAssertFalse(LockstepPair.drain(&pair.client, now: pair.now).isEmpty)
        XCTAssertEqual(pair.client.idleDeadline, received.advanced(by: .seconds(5)))
    }
}

#endif
