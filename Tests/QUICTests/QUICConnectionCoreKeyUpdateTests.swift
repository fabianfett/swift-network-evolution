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
    private static func roundTrip(
        _ pair: inout LockstepPair,
        size: Int,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
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

    /// A packet whose Key Phase bit says "update" but that doesn't open, as a forged one, keeps
    /// the keys as they are (RFC 9001 Section 6.3): a late packet of the previous phase still
    /// opens, and the genuine update after it still works.
    func testAForgedKeyUpdateKeepsThePreviousKeys() throws {
        var pair = LockstepPair()
        pair.exchange()
        Self.roundTrip(&pair, size: 10)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let chunks = (0..<3).map { [UInt8](repeating: 0x61 + UInt8($0), count: 500) }
        let (a, b, c) = (chunks[0], chunks[1], chunks[2])
        // A goes out in phase 0 and arrives late; B, in phase 1, makes the server follow.
        pair.client.write(a.span.bytes, to: streamID, fin: false)
        let late = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertTrue(pair.client.updateKeys())
        pair.client.write(b.span.bytes, to: streamID, fin: false)
        let update = LockstepPair.drain(&pair.client, now: pair.now)
        let sent = pair.now
        pair.now = pair.now.advanced(by: .milliseconds(30))
        let now = pair.now
        let acknowledgement: [[UInt8]] =
            pair.withServer { server in
                for var datagram in update {
                    var span = datagram.mutableSpan
                    server.receive(&span, now: sent)
                }
                server.handleTimeout(now: now)
                return LockstepPair.drain(&server, now: now)
            } ?? []
        XCTAssertEqual(pair.server?.keyPhase, .phase1)
        // The server's phase 1 packet lets the client update again, to phase 0: the packet that
        // carries the next generation of keys has a higher packet number than B.
        for var datagram in acknowledgement {
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: now)
        }
        XCTAssertTrue(pair.client.updateKeys())
        pair.client.write(c.span.bytes, to: streamID, fin: true)
        let nextUpdate = LockstepPair.drain(&pair.client, now: now)
        XCTAssertEqual(nextUpdate.count, 1)
        // A copy with a broken tag: its header says phase 0 and a new packet number, but it
        // doesn't open.
        var forged = try XCTUnwrap(nextUpdate.first)
        forged[forged.count - 1] ^= 0xff

        let received = pair.withServer { server in
            for var datagram in [forged] + late {
                var span = datagram.mutableSpan
                server.receive(&span, now: now)
            }
            XCTAssertEqual(server.keyPhase, .phase1, "the forged packet started an update")
            let beforeTheUpdate = Self.readAll(&server, streamID)
            for var datagram in nextUpdate {
                var span = datagram.mutableSpan
                server.receive(&span, now: now)
            }
            let afterTheUpdate = Self.readAll(&server, streamID)
            return (beforeTheUpdate.bytes, afterTheUpdate)
        }
        XCTAssertTrue(received?.0 == chunks[0] + chunks[1], "the late packet didn't open")
        XCTAssertTrue(received?.1.bytes == chunks[2], "the genuine update didn't open")
        XCTAssertEqual(received?.1.fin, true)
        XCTAssertEqual(pair.server?.keyPhase, .phase0)
        Self.roundTrip(&pair, size: 2000)
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    #if DEBUG
    private static func configuration(
        confidentialityLimit: UInt64 = .max,
        integrityLimit: UInt64 = .max
    ) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.aeadLimitsForTesting = (confidentialityLimit, integrityLimit)
        return configuration
    }

    /// RFC 9001 Section 6.6: an endpoint updates its keys before it seals more packets with them
    /// than the confidentiality limit allows.
    func testKeysUpdateBeforeTheConfidentialityLimit() {
        let limit: UInt64 = 32
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(confidentialityLimit: limit),
            serverConfiguration: Self.configuration(confidentialityLimit: limit)
        )
        pair.exchange()
        var phases: [PacketKeyState] = [pair.client.keyPhase]
        for size in [20_000, 50_000, 3000, 80_000, 100] {
            Self.roundTrip(&pair, size: size)
            if phases.last != pair.client.keyPhase { phases.append(pair.client.keyPhase) }
            XCTAssertLessThan(pair.client.packetsSealedInKeyPhase, limit)
            XCTAssertLessThan(pair.server?.packetsSealedInKeyPhase ?? limit, limit)
        }
        // The requests and responses took several times the limit in packets, each set of keys
        // sealed fewer than the limit, and the connection is still open: the keys updated.
        XCTAssertGreaterThan(phases.count, 1, "the keys didn't update")
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    /// RFC 9001 Section 6.6: once more 1-RTT packets failed to open than the integrity limit
    /// allows, the connection closes with AEAD_LIMIT_REACHED.
    func testForgedPacketsPastTheIntegrityLimitCloseTheConnection() throws {
        let limit: UInt64 = 3
        var pair = LockstepPair(clientConfiguration: Self.configuration(integrityLimit: limit))
        pair.exchange()
        Self.roundTrip(&pair, size: 10)
        let now = pair.now
        let datagrams: [[UInt8]] =
            pair.withServer { server in
                server.injectedFrames.append([0x01])  // PING
                return LockstepPair.drain(&server, now: now)
            } ?? []
        var forged = try XCTUnwrap(datagrams.first)
        forged[forged.count - 1] ^= 0xff
        for attempt in 0...limit {
            XCTAssertNil(pair.client.closeReason, "attempt \(attempt)")
            var datagram = forged
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: now)
        }
        XCTAssertEqual(
            pair.client.closeReason,
            .transportError(errorCode: 0x0f, reason: "AEAD integrity limit reached")
        )
        pair.exchange()
        XCTAssertEqual(
            pair.server?.closeReason,
            .peer(errorCode: 0x0f, isApplication: false, reason: "AEAD integrity limit reached")
        )
    }
    #endif
}

#endif
