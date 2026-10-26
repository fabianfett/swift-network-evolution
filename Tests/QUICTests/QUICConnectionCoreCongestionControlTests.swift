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

/// The congestion controllers of `QUICConnectionCore` on a connection: CUBIC by default, Prague
/// for L4S, and persistent congestion (RFC 9002 Section 7.6).
@available(Network 0.1.0, *)
final class QUICConnectionCoreCongestionControlTests: XCTestCase {
    private static func configuration(
        _ algorithm: CoreCongestionControlAlgorithm = .cubic,
        l4s: Bool = false
    ) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.congestionControl = algorithm
        configuration.ecnEnabled = true
        configuration.useECT1 = l4s
        return configuration
    }

    /// Sends `count` bytes on a new stream of the client until everything is acknowledged, with
    /// `network` seeing every datagram.
    private static func send(
        _ count: Int,
        _ pair: inout LockstepPair,
        network: (_ toServer: Bool, _ datagram: inout LockstepPair.NetworkDatagram) -> Bool = { _, _ in true }
    ) throws {
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x45, count: count).span.bytes, to: streamID, fin: true)
        for _ in 0..<20 {
            pair.exchangeWithECN(network: network)
            if pair.client.isQuiescent && pair.server?.isQuiescent != false { break }
            pair.advanceToNextDeadline()
        }
    }

    func testCubicIsTheDefault() {
        let pair = LockstepPair()
        XCTAssertEqual(pair.client.recovery.controller.algorithm, .cubic)
        XCTAssertEqual(QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options()).congestionControl, .cubic)
    }

    func testCubicReducesTheWindowByBetaForCEMarks() throws {
        var pair = LockstepPair(clientConfiguration: Self.configuration(), serverConfiguration: Self.configuration())
        pair.exchangeWithECN()
        try Self.send(20_000, &pair)
        XCTAssertEqual(pair.client.ecn.state, .capable)
        let window = pair.client.recovery.congestionWindow
        // One CE mark.
        var marked = false
        try Self.send(1_000, &pair) { toServer, datagram in
            if toServer && !marked && datagram.ecn == .ect0 {
                datagram.ecn = .ce
                marked = true
            }
            return true
        }
        XCTAssertTrue(marked)
        XCTAssertEqual(pair.client.statistics[.ecnCapablePacketsMarked], 1)
        XCTAssertEqual(pair.client.recovery.slowStartThreshold, window * 7 / 10)
    }

    func testPragueSendsECT1PacedInShortBursts() throws {
        let configuration = Self.configuration(.prague, l4s: true)
        var pair = LockstepPair(clientConfiguration: configuration, serverConfiguration: configuration)
        pair.exchangeWithECN()
        XCTAssertTrue(pair.client.isHandshakeComplete)
        XCTAssertEqual(pair.client.recovery.controller.algorithm, .prague)
        XCTAssertTrue(pair.client.configuration.pacingEnabled, "Prague always paces")
        try Self.send(20_000, &pair)
        XCTAssertEqual(pair.client.ecn.state, .capable)
        let pacer = try XCTUnwrap(pair.client.recovery.pacer)
        XCTAssertEqual(pacer.burstSize, Int(pacer.rate >> 12))

        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x45, count: 5_000).span.bytes, to: streamID, fin: true)
        var buffer = [UInt8](repeating: 0, count: 1500)
        var span = buffer.mutableSpan
        XCTAssertNotNil(pair.client.send(into: &span, now: pair.now))
        XCTAssertEqual(pair.client.lastDatagramECN, .ect1)
        XCTAssertNotNil(pair.client.departureTime)
    }

    func testPragueReducesByLittleForRareMarks() throws {
        let configuration = Self.configuration(.prague, l4s: true)
        var pair = LockstepPair(clientConfiguration: configuration, serverConfiguration: configuration)
        pair.exchangeWithECN()
        // Rounds without marks bring α down from one.
        for _ in 0..<30 {
            try Self.send(20_000, &pair)
        }
        XCTAssertEqual(pair.client.ecn.state, .capable)
        guard case .prague(let before) = pair.client.recovery.controller else { return XCTFail("Not Prague") }
        XCTAssertLessThan(before.alpha, CorePrague.maxAlpha / 4)
        let window = pair.client.recovery.congestionWindow

        var marked = false
        try Self.send(1_000, &pair) { toServer, datagram in
            if toServer && !marked && datagram.ecn == .ect1 {
                datagram.ecn = .ce
                marked = true
            }
            return true
        }
        XCTAssertTrue(marked)
        guard case .prague(let after) = pair.client.recovery.controller else { return XCTFail("Not Prague") }
        XCTAssertTrue(after.reducedForCE)
        // The window shrank by α/2, much less than CUBIC's 30 %.
        let threshold = pair.client.recovery.slowStartThreshold
        XCTAssertLessThan(threshold, window)
        XCTAssertGreaterThan(threshold, window * 3 / 4)
    }

    func testAnOutageOfThreePTOsCollapsesTheWindow() throws {
        var pair = LockstepPair()
        pair.exchange()
        // RTT samples, and a window that grew.
        let first = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x45, count: 30_000).span.bytes, to: first, fin: true)
        pair.exchange()
        XCTAssertTrue(pair.client.recovery.hasRTTSample)
        XCTAssertGreaterThan(pair.client.recovery.congestionWindow, pair.client.recovery.minimumWindow)

        // Nothing gets through for longer than three PTOs.
        let second = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x46, count: 5_000).span.bytes, to: second, fin: true)
        let start = pair.now
        let duration = pair.client.recovery.persistentCongestionDuration
        while pair.now < start.advanced(by: duration * 2) {
            pair.exchange(drop: { toServer, _ in toServer })
            pair.advanceToNextDeadline()
        }
        XCTAssertGreaterThanOrEqual(pair.client.recovery.ptoCount, 2)

        // The first ACK after the outage declares everything in between lost.
        let probes = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertFalse(probes.isEmpty)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        for var datagram in probes {
            var span = datagram.mutableSpan
            server.receive(&span, now: pair.now)
        }
        let acknowledgements = LockstepPair.drain(&server, now: pair.now)
        pair.server = consume server
        var acknowledgement = try XCTUnwrap(acknowledgements.first)
        var span = acknowledgement.mutableSpan
        pair.client.receive(&span, now: pair.now)
        XCTAssertEqual(pair.client.recovery.congestionWindow, pair.client.recovery.minimumWindow)
        XCTAssertNil(pair.client.recovery.congestionRecoveryStartTime)
        XCTAssertEqual(pair.client.recovery.minRTT, pair.client.recovery.latestRTT)
    }
}

#endif
