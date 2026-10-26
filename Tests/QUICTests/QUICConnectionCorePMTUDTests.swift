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

/// Path MTU discovery in `QUICConnectionCore` (RFC 9000 Section 14.3, RFC 8899).
@available(Network 0.1.0, *)
final class QUICConnectionCorePMTUDTests: XCTestCase {
    /// An IPv4 path: 28 bytes of IP and UDP headers.
    private static let headerSize = 28

    private static func configuration(
        interfaceMTU: Int = 9216,
        interval: NetworkDuration = .seconds(600),
        ignoreCost: Bool = true
    ) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.maxDatagramSize = 1200
        configuration.pmtudEnabled = true
        configuration.pmtudIgnoreCost = ignoreCost
        configuration.pmtudInterval = interval
        configuration.interfaceMTU = interfaceMTU
        configuration.ipUDPHeaderSize = Self.headerSize
        return configuration
    }

    private static func pair(
        client: QUICConnectionCore.Configuration = configuration(),
        server: QUICConnectionCore.Configuration = configuration(),
        linkMTU: Int
    ) -> LockstepPair {
        var pair = LockstepPair(clientConfiguration: client, serverConfiguration: server)
        pair.linkMaxDatagramSize = linkMTU - Self.headerSize
        return pair
    }

    /// Exchanges datagrams and fires timers until neither side searches any more, or `limit`
    /// rounds passed.
    private static func searchUntilDone(_ pair: inout LockstepPair, limit: Int = 100) {
        for _ in 0..<limit {
            pair.exchange()
            let clientSearching = pair.client.paths[pair.client.activePathID]?.pmtud?.isSearching ?? false
            var serverSearching = false
            if let server = pair.server.take() {
                serverSearching = server.paths[server.activePathID]?.pmtud?.isSearching ?? false
                pair.server = consume server
            }
            guard clientSearching || serverSearching else { return }
            pair.advanceToNextDeadline()
        }
    }

    // MARK: CorePMTUD

    func testTheLadderGoesToTheNextLargerSize() {
        XCTAssertEqual(CorePMTUD.nextMTU(above: 1228), 1280)
        XCTAssertEqual(CorePMTUD.nextMTU(above: 1280), 1300)
        XCTAssertEqual(CorePMTUD.nextMTU(above: 1301), 1350)
        XCTAssertEqual(CorePMTUD.nextMTU(above: 1492), 1500)
        XCTAssertEqual(CorePMTUD.nextMTU(above: 1500), 9216)
        XCTAssertEqual(CorePMTUD.nextMTU(above: 9216), 0)
    }

    func testTheSearchIsCappedByTheInterfaceAndThePeersLimit() {
        var pmtud = CorePMTUD(baseDatagramSize: 1200, ipUDPHeaderSize: 28)
        pmtud.start(interfaceMTU: 1400, peerMaxUDPPayloadSize: 65527, firstPacketNumber: 0)
        XCTAssertEqual(pmtud.maximumMTU, 1400)
        pmtud.start(interfaceMTU: 9000, peerMaxUDPPayloadSize: 1300, firstPacketNumber: 0)
        XCTAssertEqual(pmtud.maximumMTU, 1328)
        // An unknown interface MTU allows the IPv6 minimum.
        pmtud.start(interfaceMTU: 0, peerMaxUDPPayloadSize: 65527, firstPacketNumber: 0)
        XCTAssertEqual(pmtud.maximumMTU, 1280)
        XCTAssertEqual(pmtud.probeDatagramSize, 1252)
        // A path that already carries the maximum has nothing to search.
        var atMaximum = CorePMTUD(baseDatagramSize: 1472, ipUDPHeaderSize: 28)
        atMaximum.start(interfaceMTU: 1500, peerMaxUDPPayloadSize: 65527, firstPacketNumber: 0)
        XCTAssertFalse(atMaximum.isSearching)
        XCTAssertFalse(atMaximum.probePending)
    }

    func testALostProbeIsRetriedAndThreeLossesEndTheSearch() {
        var pmtud = CorePMTUD(baseDatagramSize: 1252, ipUDPHeaderSize: 28)
        let now = NetworkClock.Instant(milliseconds: 1_000)
        pmtud.start(interfaceMTU: 1500, peerMaxUDPPayloadSize: 65527, firstPacketNumber: 10)
        XCTAssertEqual(pmtud.probeMTU, 1300)
        pmtud.probeSent()
        XCTAssertFalse(pmtud.probePending)
        // An acknowledgement of a probe of an earlier search changes nothing.
        XCTAssertNil(pmtud.probeAcknowledged(datagramSize: 1272, packetNumber: 9, interval: .seconds(1), now: now))
        XCTAssertEqual(pmtud.probeAcknowledged(datagramSize: 1272, packetNumber: 10, interval: .seconds(1), now: now), 1272)
        XCTAssertEqual(pmtud.probeMTU, 1350)
        for attempt in 1...3 {
            XCTAssertTrue(pmtud.probePending, "attempt \(attempt)")
            XCTAssertEqual(pmtud.probeMTU, 1350, "the same size again")
            pmtud.probeSent()
            pmtud.probeLost(datagramSize: 1322, packetNumber: UInt64(10 + attempt), interval: .seconds(1), now: now)
        }
        XCTAssertFalse(pmtud.isSearching)
        XCTAssertFalse(pmtud.probePending)
        XCTAssertEqual(pmtud.maxDatagramSize, 1272)
        XCTAssertEqual(pmtud.raiseDeadline, now.advanced(by: .seconds(1)))
        pmtud.raiseTimerFired(firstPacketNumber: 20)
        XCTAssertTrue(pmtud.isSearching)
        XCTAssertEqual(pmtud.probeMTU, 1350)
        XCTAssertNil(pmtud.raiseDeadline)
    }

    func testBlackholeDetectionFallsBackToTheBaseSize() {
        var pmtud = CorePMTUD(baseDatagramSize: 1200, ipUDPHeaderSize: 28)
        XCTAssertFalse(pmtud.enterBlackholeDetection(firstPacketNumber: 0), "nothing to fall back from")
        pmtud.start(interfaceMTU: 1500, peerMaxUDPPayloadSize: 65527, firstPacketNumber: 0)
        pmtud.probeSent()
        _ = pmtud.probeAcknowledged(
            datagramSize: 1252,
            packetNumber: 0,
            interval: .seconds(1),
            now: NetworkClock.Instant(milliseconds: 1_000)
        )
        XCTAssertEqual(pmtud.maxDatagramSize, 1252)
        XCTAssertTrue(pmtud.enterBlackholeDetection(firstPacketNumber: 5))
        XCTAssertEqual(pmtud.maxDatagramSize, 1200)
        XCTAssertTrue(pmtud.probePending)
        XCTAssertEqual(pmtud.probeMTU, 1280)
    }

    // MARK: Lockstep

    func testProbesClimbTheLadderToTheLinkMTU() throws {
        var pair = Self.pair(linkMTU: 1500)
        Self.searchUntilDone(&pair)
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        XCTAssertEqual(pair.client.maxDatagramSize, 1500 - Self.headerSize)
        XCTAssertEqual(pair.client.recovery.maxDatagramSize, 1500 - Self.headerSize)
        // Only the probes for 9216 bytes were too large, three in each direction.
        XCTAssertEqual(pair.droppedForSize.toServer, [9188, 9188, 9188])
        XCTAssertEqual(pair.droppedForSize.toClient, [9188, 9188, 9188])
        let pmtud = try XCTUnwrap(pair.client.paths[pair.client.activePathID]?.pmtud)
        XCTAssertFalse(pmtud.isSearching)
        XCTAssertNotNil(pmtud.raiseDeadline, "9216 bytes may work later")
        guard let server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(server.maxDatagramSize, 1500 - Self.headerSize)
        pair.server = consume server

        // The larger datagrams carry stream data.
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x42, count: 20_000).span.bytes, to: streamID, fin: true)
        let sizes = LockstepPair.drain(&pair.client, now: pair.now).map(\.count)
        XCTAssertLessThanOrEqual(sizes.max() ?? 0, 1500 - Self.headerSize)
        XCTAssertGreaterThan(sizes.first ?? 0, 1400)
    }

    func testLostProbesAreRetriedAndLeaveTheCongestionWindowAlone() throws {
        var pair = Self.pair(linkMTU: 1300)
        Self.searchUntilDone(&pair)
        XCTAssertEqual(pair.client.maxDatagramSize, 1300 - Self.headerSize)
        // The probe for 1350 bytes went out three times.
        XCTAssertEqual(pair.droppedForSize.toServer, [1322, 1322, 1322])
        XCTAssertGreaterThanOrEqual(pair.client.statistics[.txLostPackets], 3)
        // RFC 9000 Section 14.4: a lost probe is no congestion signal.
        XCTAssertNil(pair.client.recovery.congestionRecoveryStartTime)
        XCTAssertEqual(pair.client.recovery.slowStartThreshold, .max)
    }

    func testTheSearchStartsOverAfterTheInterval() throws {
        var pair = Self.pair(
            client: Self.configuration(interval: .milliseconds(500)),
            server: Self.configuration(interval: .seconds(600)),
            linkMTU: 1300
        )
        Self.searchUntilDone(&pair)
        XCTAssertEqual(pair.client.maxDatagramSize, 1300 - Self.headerSize)
        let deadline = try XCTUnwrap(pair.client.paths[pair.client.activePathID]?.pmtud?.raiseDeadline)
        XCTAssertEqual(pair.client.nextDeadline.map { $0 <= deadline }, true)

        // The path carries more now.
        pair.linkMaxDatagramSize = 1400 - Self.headerSize
        pair.now = deadline
        pair.client.handleTimeout(now: pair.now)
        XCTAssertEqual(pair.client.paths[pair.client.activePathID]?.pmtud?.isSearching, true)
        Self.searchUntilDone(&pair)
        XCTAssertEqual(pair.client.maxDatagramSize, 1390 - Self.headerSize)
    }

    func testLostFullSizePacketsFallBackToTheBaseSizeAndSearchAgain() throws {
        var pair = Self.pair(linkMTU: 1500)
        Self.searchUntilDone(&pair)
        XCTAssertEqual(pair.client.maxDatagramSize, 1500 - Self.headerSize)

        // The path stops carrying more than 1280 bytes. ACKs and short packets still get through,
        // so it takes the losses of full-size packets to notice.
        pair.linkMaxDatagramSize = 1280 - Self.headerSize
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let payload = [UInt8](repeating: 0x42, count: 20_000)
        pair.client.write(payload.span.bytes, to: streamID, fin: true)
        for _ in 0..<40 {
            pair.exchange()
            if pair.serverEvents.contains(.streamReadable(streamID)),
                pair.client.paths[pair.client.activePathID]?.pmtud?.isSearching == false
            {
                break
            }
            pair.advanceToNextDeadline()
        }
        XCTAssertGreaterThanOrEqual(pair.droppedForSize.toServer.count, CorePMTUD.blackholeLosses)
        XCTAssertTrue(pair.serverEvents.contains(.streamReadable(streamID)), "the data arrives at the smaller size")
        // The search from the base size found the new limit.
        XCTAssertEqual(pair.client.maxDatagramSize, 1280 - Self.headerSize)
    }

    func testLostFullSizePacketsFallBackBeforeAnyPTO() throws {
        var pair = Self.pair(linkMTU: 1500)
        Self.searchUntilDone(&pair)
        XCTAssertEqual(pair.client.maxDatagramSize, 1500 - Self.headerSize)
        let timeouts = pair.client.statistics[.probeTimeOuts]
        pair.linkMaxDatagramSize = 1280 - Self.headerSize
        // A window's worth of full-size packets, then a PING that gets through and whose ACK
        // declares them lost. No timer fires.
        pair.client.recovery.congestion.congestionWindow = 40_000
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x42, count: 12 * 1400).span.bytes, to: streamID, fin: true)
        pair.toServer += LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertGreaterThanOrEqual(pair.toServer.count, CorePMTUD.blackholeLosses + 2)
        pair.client.pingPending = true
        pair.toServer += LockstepPair.drain(&pair.client, now: pair.now)
        pair.now = pair.now.advanced(by: .milliseconds(2))
        pair.exchange()
        XCTAssertEqual(pair.client.statistics[.probeTimeOuts], timeouts)
        XCTAssertLessThan(pair.client.maxDatagramSize, 1500 - Self.headerSize)
    }

    func testTenFullSizePacketsLostInARowFallBackToTheBaseSize() throws {
        var pair = Self.pair(linkMTU: 1500)
        Self.searchUntilDone(&pair)
        XCTAssertEqual(pair.client.maxDatagramSize, 1500 - Self.headerSize)
        // An acknowledged full-size packet in between starts the count over.
        for _ in 1..<CorePMTUD.blackholeLosses {
            pair.client.pmtudLargePacket(acknowledged: false)
        }
        pair.client.pmtudLargePacket(acknowledged: true)
        for _ in 1..<CorePMTUD.blackholeLosses {
            pair.client.pmtudLargePacket(acknowledged: false)
        }
        XCTAssertEqual(pair.client.maxDatagramSize, 1500 - Self.headerSize)
        pair.client.pmtudLargePacket(acknowledged: false)
        XCTAssertEqual(pair.client.maxDatagramSize, 1200)
        XCTAssertEqual(pair.client.paths[pair.client.activePathID]?.pmtud?.probePending, true)
    }

    func testPTOsFallBackToTheBaseSize() throws {
        var pair = Self.pair(linkMTU: 1500)
        Self.searchUntilDone(&pair)
        XCTAssertEqual(pair.client.maxDatagramSize, 1500 - Self.headerSize)

        // Nothing gets through for a while.
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x42, count: 2_000).span.bytes, to: streamID, fin: true)
        for _ in 0..<(CorePMTUD.blackholeThreshold + 1) {
            XCTAssertEqual(pair.client.maxDatagramSize, 1500 - Self.headerSize)
            pair.exchange(drop: { toServer, _ in toServer })
            pair.advanceToNextDeadline()
        }
        XCTAssertEqual(pair.client.recovery.ptoCount, CorePMTUD.blackholeThreshold + 1)
        XCTAssertEqual(pair.client.maxDatagramSize, 1200)
        XCTAssertEqual(pair.client.recovery.maxDatagramSize, 1200)

        // Once the path is back, the search climbs again.
        Self.searchUntilDone(&pair)
        XCTAssertTrue(pair.serverEvents.contains(.streamReadable(streamID)))
        XCTAssertEqual(pair.client.maxDatagramSize, 1500 - Self.headerSize)
    }

    func testWithoutPMTUDNoProbeGoesOut() {
        var configuration = Self.configuration()
        configuration.pmtudEnabled = false
        var pair = Self.pair(client: configuration, server: configuration, linkMTU: 1500)
        Self.searchUntilDone(&pair)
        XCTAssertEqual(pair.client.maxDatagramSize, 1200)
        XCTAssertNil(pair.client.paths[pair.client.activePathID]?.pmtud)
        XCTAssertEqual(pair.client.datagramCapacity, 1200)
    }

    func testTheCostCheckWaitsForEnoughQueuedData() throws {
        let configuration = Self.configuration(ignoreCost: false)
        var pair = Self.pair(client: configuration, server: configuration, linkMTU: 1500)
        pair.exchange()
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        XCTAssertEqual(pair.client.paths[pair.client.activePathID]?.pmtud?.probePending, true)
        // Nothing queued: a probe doesn't pay off.
        XCTAssertEqual(pair.client.maxDatagramSize, 1200)
        XCTAssertEqual(pair.client.datagramCapacity, 1252, "the buffer for the probe")
        XCTAssertTrue(LockstepPair.drain(&pair.client, now: pair.now).isEmpty)

        // Enough data to save a probe's worth of headers.
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x42, count: 1_000_000).span.bytes, to: streamID, fin: true)
        let datagrams = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertEqual(datagrams.first?.count, 1252, "the probe goes first")
    }

    /// The delayed ACK timer firing while a probe is due sends both. The probe carries only PING
    /// and PADDING (RFC 9000 Section 14.4), so the ACK goes first, within the delay the peer
    /// expects (RFC 9000 Section 13.2.1), and the probe right after it.
    func testTheDelayedAckTimerSendsAProbeAndTheAck() throws {
        var pair = Self.pair(client: Self.configuration(interval: .milliseconds(500)), linkMTU: 1300)
        Self.searchUntilDone(&pair)
        let baseSize = pair.client.maxDatagramSize
        XCTAssertEqual(baseSize, 1300 - Self.headerSize)
        // The next search is due, which leaves a probe to send.
        pair.now = try XCTUnwrap(pair.client.paths[pair.client.activePathID]?.pmtud?.raiseDeadline)
        pair.client.handleTimeout(now: pair.now)
        XCTAssertEqual(pair.client.paths[pair.client.activePathID]?.pmtud?.probePending, true)

        // One ack-eliciting packet from the server, which the client acknowledges with a delay.
        guard var server = pair.server.take() else { return XCTFail("No server") }
        let streamID = try XCTUnwrap(server.openStream(bidirectional: true))
        XCTAssertEqual(server.write([UInt8]([0x42]).span.bytes, to: streamID), 1)
        let toClient = LockstepPair.drain(&server, now: pair.now)
        pair.server = consume server
        XCTAssertEqual(toClient.count, 1)
        for var datagram in toClient {
            var span = datagram.mutableSpan
            pair.client.receive(&span, on: pair.client.activePathID, ecn: .nonECT, now: pair.now)
        }
        let ackDeadline = try XCTUnwrap(pair.client.acks[.applicationData].ackDeadline)
        XCTAssertFalse(pair.client.acks[.applicationData].ackNeeded)

        // The delayed ACK timer fires.
        pair.now = ackDeadline
        pair.client.handleTimeout(now: pair.now)
        let datagrams = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertEqual(datagrams.count, 2, "the ACK, then the probe: \(datagrams.map(\.count))")
        XCTAssertLessThan(datagrams.first?.count ?? .max, 100, "the ACK goes first")
        XCTAssertGreaterThan(datagrams.last?.count ?? 0, baseSize, "the probe follows")
        XCTAssertFalse(pair.client.acks[.applicationData].ackNeeded, "the ACK went out")
        XCTAssertNil(pair.client.acks[.applicationData].ackDeadline)
    }
}

#endif
