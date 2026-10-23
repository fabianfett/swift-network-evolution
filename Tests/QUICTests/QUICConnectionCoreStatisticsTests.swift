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

/// The statistics and the latency spin bit of `QUICConnectionCore`.
@available(Network 0.1.0, *)
final class QUICConnectionCoreStatisticsTests: XCTestCase {
    private static func readAll(_ machine: inout QUICConnectionCore, from streamID: UInt64) -> Int {
        var received = 0
        while true {
            let progress: Int =
                machine.read(from: streamID) { bytes, _ in
                    received += bytes.byteCount
                    return (bytes.byteCount, bytes.byteCount)
                } ?? 0
            if progress == 0 { return received }
        }
    }

    func testStreamAndCryptoFramesAreCounted() throws {
        var pair = LockstepPair()
        pair.exchange()
        XCTAssertEqual(pair.client.statistics[.txInitialCryptoFrames], 1)
        XCTAssertEqual(pair.client.statistics[.txHandshakeCryptoFrames], 1)
        XCTAssertEqual(pair.client.statistics[.rxInitialCryptoFrames], 1)
        XCTAssertGreaterThan(pair.client.statistics[.rxHandshakeCryptoBytes], 0)
        XCTAssertEqual(pair.client.statistics[.txInitialCryptoBytes], pair.server?.statistics[.rxInitialCryptoBytes])

        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let payload = [UInt8](repeating: 1, count: 3000)
        pair.client.write(payload.span.bytes, to: streamID, fin: true)
        pair.exchange()
        XCTAssertEqual(pair.client.statistics[.txStreamBytes], 3000)
        XCTAssertGreaterThanOrEqual(pair.client.statistics[.txStreamFrames], 3)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(server.statistics[.rxStreamBytes], 3000)
        XCTAssertEqual(server.statistics[.rxStreamFrames], pair.client.statistics[.txStreamFrames])
        XCTAssertEqual(Self.readAll(&server, from: streamID), 3000)
        pair.server = consume server
        XCTAssertEqual(pair.client.statistics[.txLostPackets], 0)
        XCTAssertEqual(pair.client.statistics[.txRetransmittedBytes], 0)
    }

    func testLossAndRetransmissionsAreCounted() throws {
        var pair = LockstepPair()
        pair.exchange()
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 2, count: 5000).span.bytes, to: streamID, fin: true)
        // The first datagram towards the server is lost.
        var dropped = false
        pair.exchange(drop: { toServer, _ in
            guard toServer, !dropped else { return false }
            dropped = true
            return true
        })
        for _ in 0..<5 where pair.client.recovery.hasAckElicitingInFlight {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        XCTAssertGreaterThanOrEqual(pair.client.statistics[.txLostPackets], 1)
        XCTAssertGreaterThan(pair.client.statistics[.txLostBytes], 0)
        XCTAssertGreaterThan(pair.client.statistics[.txRetransmittedBytes], 0)
        XCTAssertEqual(
            pair.client.statistics[.txStreamBytes],
            5000 + pair.client.statistics[.txRetransmittedBytes]
        )
    }

    func testResetsAndStopsAreCounted() throws {
        var pair = LockstepPair()
        pair.exchange()
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 3, count: 10).span.bytes, to: streamID)
        pair.exchange()
        pair.client.resetStream(streamID, errorCode: 1)
        pair.client.stopSending(streamID, errorCode: 2)
        pair.exchange()
        XCTAssertEqual(pair.client.statistics[.txStreamResetFrames], 1)
        XCTAssertEqual(pair.client.statistics[.txStreamStopSendingFrames], 1)
        XCTAssertEqual(pair.server?.statistics[.rxStreamResetFrames], 1)
        XCTAssertEqual(pair.server?.statistics[.rxStreamStopSendingFrames], 1)
    }

    // MARK: Spin bit

    /// The spin bit of each short header datagram.
    private static func spinBits(_ datagrams: [[UInt8]]) -> [Bool] {
        datagrams.filter { $0[0] & 0xc0 == 0x40 }.map { $0[0] & 0x20 != 0 }
    }

    private static func spinningPair(enabled: Bool, value: Bool = false) -> LockstepPair {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.spinBitEnabled = enabled
        configuration.spinValue = value
        var pair = LockstepPair(clientConfiguration: configuration, serverConfiguration: configuration)
        pair.exchange()
        return pair
    }

    /// RFC 9000 Section 17.4: the server reflects the spin bit, the client inverts what it
    /// receives, so the client's value flips once per round trip.
    func testTheSpinBitFlipsOncePerRoundTrip() throws {
        var pair = Self.spinningPair(enabled: true)
        var clientBits: [Bool] = []
        var serverBits: [Bool] = []
        for round in 0..<4 {
            pair.client.injectedFrames.append([0x01])
            let fromClient = LockstepPair.drain(&pair.client, now: pair.now)
            clientBits += Self.spinBits(fromClient)
            guard var server = pair.server.take() else { return XCTFail("No server") }
            for var datagram in fromClient {
                var span = datagram.mutableSpan
                server.receive(&span, now: pair.now)
            }
            server.injectedFrames.append([0x01])
            let fromServer = LockstepPair.drain(&server, now: pair.now)
            serverBits += Self.spinBits(fromServer)
            pair.server = consume server
            for var datagram in fromServer {
                var span = datagram.mutableSpan
                pair.client.receive(&span, now: pair.now)
            }
            XCTAssertEqual(clientBits.count, round + 1)
        }
        // The server echoes each round's client value; the client alternates.
        XCTAssertEqual(serverBits, clientBits)
        for index in 1..<clientBits.count {
            XCTAssertNotEqual(clientBits[index], clientBits[index - 1], "round \(index): \(clientBits)")
        }
    }

    func testADisabledSpinBitKeepsItsValue() throws {
        for value in [false, true] {
            var pair = Self.spinningPair(enabled: false, value: value)
            var bits: [Bool] = []
            for _ in 0..<3 {
                pair.client.injectedFrames.append([0x01])
                let datagrams = LockstepPair.drain(&pair.client, now: pair.now)
                bits += Self.spinBits(datagrams)
                pair.toServer = datagrams
                pair.exchange()
            }
            XCTAssertFalse(bits.isEmpty)
            XCTAssertEqual(Set(bits), [value])
        }
    }
}

#endif
