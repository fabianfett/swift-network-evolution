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

/// Key updates (RFC 9001 Section 6) between two cores.
@available(Network 0.1.0, *)
final class QUICConnectionCoreKeyUpdateTests: XCTestCase {
    /// Reads everything readable on `streamID`.
    private static func readAll(_ core: inout QUICConnectionCore, _ streamID: UInt64) -> (bytes: [UInt8], fin: Bool) {
        var bytes: [UInt8] = []
        var fin = false
        while true {
            let consumed: Int? = core.read(from: streamID) { span, isFinished in
                bytes += [UInt8](copying: span)
                if isFinished { fin = true }
                return (span.byteCount, span.byteCount)
            }
            guard let consumed, consumed > 0 else { break }
        }
        return (bytes, fin)
    }

    /// Sends a request on a new stream, echoes it back, and checks that both directions arrive.
    private static func roundTrip(_ pair: inout LockstepPair, size: Int, file: StaticString = #filePath, line: UInt = #line)
    {
        guard let streamID = pair.client.openStream(bidirectional: true) else {
            XCTFail("No stream", file: file, line: line)
            return
        }
        let request = (0..<size).map { UInt8(truncatingIfNeeded: $0 &* 13 &+ Int(streamID)) }
        XCTAssertEqual(pair.client.write(request.span.bytes, to: streamID, fin: true), size, file: file, line: line)
        pair.exchange()
        let received = pair.withServer { server in
            let received = Self.readAll(&server, streamID)
            server.write(received.bytes.span.bytes, to: streamID, fin: true)
            return received
        }
        XCTAssertTrue(received?.bytes == request, "request bytes", file: file, line: line)
        XCTAssertEqual(received?.fin, true, file: file, line: line)
        pair.exchange()
        let response = Self.readAll(&pair.client, streamID)
        XCTAssertTrue(response.bytes == request, "response bytes", file: file, line: line)
        XCTAssertTrue(response.fin, file: file, line: line)
    }

    func testThePeerFollowsAKeyUpdate() {
        var pair = LockstepPair()
        pair.exchange()
        Self.roundTrip(&pair, size: 3000)
        XCTAssertEqual(pair.client.keyPhase, .phase0)

        XCTAssertTrue(pair.client.updateKeys())
        XCTAssertEqual(pair.client.keyPhase, .phase1)
        Self.roundTrip(&pair, size: 20_000)
        XCTAssertEqual(pair.server?.keyPhase, .phase1)
        XCTAssertEqual(pair.client.keyPhase, .phase1)
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testBothSidesUpdateTheKeysAgainAndAgain() {
        var pair = LockstepPair()
        pair.exchange()
        Self.roundTrip(&pair, size: 100)
        for generation in 1...6 {
            if generation % 2 == 0 {
                XCTAssertEqual(pair.withServer { $0.updateKeys() }, true, "generation \(generation)")
            } else {
                XCTAssertTrue(pair.client.updateKeys(), "generation \(generation)")
            }
            Self.roundTrip(&pair, size: 1000 * generation)
            let phase: PacketKeyState = generation % 2 == 1 ? .phase1 : .phase0
            XCTAssertEqual(pair.client.keyPhase, phase, "generation \(generation)")
            XCTAssertEqual(pair.server?.keyPhase, phase, "generation \(generation)")
        }
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testAKeyUpdateWaitsForTheHandshakeAndForThePeerToFollow() {
        var pair = LockstepPair()
        XCTAssertFalse(pair.client.updateKeys(), "before the handshake")
        pair.exchange()
        XCTAssertTrue(pair.client.updateKeys())
        XCTAssertFalse(pair.client.updateKeys(), "the server hasn't sent a packet in the new phase yet")
        XCTAssertEqual(pair.client.keyPhase, .phase1)
        Self.roundTrip(&pair, size: 10)
        XCTAssertTrue(pair.client.updateKeys(), "the server followed")
        XCTAssertEqual(pair.client.keyPhase, .phase0)
        Self.roundTrip(&pair, size: 10)
        XCTAssertEqual(pair.server?.keyPhase, .phase0)
    }

    /// A packet sent before the update but delivered after one sent after it still opens with the
    /// previous keys, and doesn't start another update.
    func testAPacketFromBeforeTheUpdateArrivingLateStillOpens() throws {
        var pair = LockstepPair()
        pair.exchange()
        Self.roundTrip(&pair, size: 10)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let first = [UInt8](repeating: 0x61, count: 500)
        let second = [UInt8](repeating: 0x62, count: 500)
        pair.client.write(first.span.bytes, to: streamID, fin: false)
        let before = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertEqual(before.count, 1)
        XCTAssertTrue(pair.client.updateKeys())
        pair.client.write(second.span.bytes, to: streamID, fin: true)
        let after = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertEqual(after.count, 1)
        // The first byte's Key Phase bit is under header protection, so check the core's state.
        XCTAssertEqual(pair.client.keyPhase, .phase1)

        let now = pair.now
        let received = pair.withServer { server in
            for var datagram in after + before {
                var span = datagram.mutableSpan
                server.receive(&span, now: now)
            }
            return Self.readAll(&server, streamID)
        }
        // Both arrived without a retransmission.
        XCTAssertTrue(received?.bytes == first + second, "received \(received?.bytes.count ?? -1) bytes")
        XCTAssertEqual(received?.fin, true)
        XCTAssertEqual(pair.server?.keyPhase, .phase1)
        pair.exchange()
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }
}

#endif
