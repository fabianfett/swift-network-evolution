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

/// ECN in `QUICConnectionCore`: marking, validation (RFC 9000 Section 13.4) and the reaction to
/// CE marks (RFC 9002 Section 7.1).
@available(Network 0.1.0, *)
final class QUICConnectionCoreECNTests: XCTestCase {
    private static let newPath = CorePathID(1)

    private static func configuration(marking: Bool = true, echo: Bool = true) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.ecnEnabled = marking
        configuration.ecnEchoEnabled = echo
        configuration.automaticallyIssueConnectionIDs = true
        configuration.activeConnectionIDLimit = 4
        return configuration
    }

    private typealias Network = (_ toServer: Bool, _ datagram: inout LockstepPair.NetworkDatagram) -> Bool

    /// Completes the handshake, confirms it and hands out the connection IDs.
    private static func connectedPair(
        client: QUICConnectionCore.Configuration = configuration(),
        server: QUICConnectionCore.Configuration = configuration(),
        network: Network = { _, _ in true }
    ) -> LockstepPair {
        var pair = LockstepPair(clientConfiguration: client, serverConfiguration: server)
        pair.exchangeWithECN(network: network)
        pair.exchangeWithECN(network: network)
        return pair
    }

    /// Sends `count` bytes on a new stream of the client, until everything is acknowledged.
    @discardableResult
    private static func send(
        _ count: Int,
        _ pair: inout LockstepPair,
        network: Network = { _, _ in true }
    ) throws -> UInt64 {
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x45, count: count).span.bytes, to: streamID, fin: true)
        for _ in 0..<20 {
            pair.exchangeWithECN(network: network)
            // The idle timeout would be next.
            if pair.client.isQuiescent && pair.server?.isQuiescent != false { break }
            pair.advanceToNextDeadline()
        }
        return streamID
    }

    /// The bytes the server read from a stream.
    private static func serverRead(_ streamID: UInt64, _ pair: inout LockstepPair) -> Int {
        guard var server = pair.server.take() else { return 0 }
        var received = 0
        while let progress: Int = server.read(
            from: streamID,
            { bytes, _ in
                received += bytes.byteCount
                return (bytes.byteCount, bytes.byteCount)
            }
        ), progress > 0 {}
        pair.server = consume server
        return received
    }

    // MARK: Validation

    func testValidationSucceedsWithAPeerThatEchoesTheCounts() throws {
        var pair = Self.connectedPair()
        XCTAssertEqual(pair.client.ecn.state, .probingValidated)
        XCTAssertGreaterThan(pair.client.statistics[.ecnCapablePacketsSent], 0)
        XCTAssertGreaterThan(pair.client.statistics[.ecnCapablePacketsAcknowledged], 0)

        var codepoints: [IPProtocol.ECN] = []
        let streamID = try Self.send(
            20_000,
            &pair,
            network: { toServer, datagram in
                if toServer { codepoints.append(datagram.ecn) }
                return true
            }
        )
        XCTAssertEqual(Self.serverRead(streamID, &pair), 20_000)
        XCTAssertEqual(pair.client.ecn.state, .capable)
        XCTAssertEqual(codepoints.first, .ect0)
        XCTAssertFalse(codepoints.contains(.ect1))
        XCTAssertFalse(codepoints.contains(.ce))
        // Once capable, every datagram is marked, the ACK-only ones too.
        XCTAssertEqual(pair.client.lastDatagramECN, .ect0)
        XCTAssertGreaterThanOrEqual(pair.client.ecn.validationPacketsSent, CoreECNValidator.validationPacketCount)
        // The server counted what arrived marked and reported it.
        let serverReceived = try XCTUnwrap(pair.server?.statistics[.rxECT0])
        XCTAssertGreaterThan(serverReceived, 10)
        let echoed = try XCTUnwrap(pair.server?.acks[.applicationData].ecnCounts.ect0)
        XCTAssertGreaterThan(echoed, 0)
        XCTAssertLessThanOrEqual(echoed, UInt64(serverReceived))
        let sent = pair.client.recovery.spaces[Int(PacketNumberSpace.applicationData.rawValue)].ecnCapableSent
        let feedback = pair.client.recovery.spaces[Int(PacketNumberSpace.applicationData.rawValue)].ecnFeedback
        XCTAssertGreaterThan(feedback.ect0, 0)
        XCTAssertLessThanOrEqual(feedback.ect0, sent)
        XCTAssertEqual(pair.client.statistics[.ecnCapablePacketsMarked], 0)
        XCTAssertEqual(pair.client.statistics[.ecnCapablePacketsLost], 0)
        XCTAssertEqual(pair.client.statistics[.ecnCapablePacketsSent], pair.client.statistics[.txECT0])
        XCTAssertNil(pair.client.recovery.congestionRecoveryStartTime)
    }

    func testAPeerThatDoesNotEchoMakesECNUnsupported() throws {
        var pair = Self.connectedPair(server: Self.configuration(marking: false, echo: false))
        XCTAssertEqual(pair.client.ecn.state, .unsupported)
        XCTAssertEqual(pair.server?.ecn.state, .disabled)
        XCTAssertEqual(pair.server?.statistics[.rxECT0], 0)
        var codepoints: [IPProtocol.ECN] = []
        let streamID = try Self.send(
            5000,
            &pair,
            network: { toServer, datagram in
                if toServer { codepoints.append(datagram.ecn) }
                return true
            }
        )
        XCTAssertEqual(Self.serverRead(streamID, &pair), 5000)
        XCTAssertFalse(codepoints.isEmpty)
        XCTAssertEqual(Set(codepoints), [.nonECT], "marking stops once validation failed")
    }

    /// RFC 9000 Section 13.4.2.1: a path that clears the marks, or sets the codepoint this endpoint
    /// never uses, fails validation.
    func testAPathThatRewritesTheCodepointMakesECNUnsupported() throws {
        for rewritten in [IPProtocol.ECN.nonECT, .ect1] {
            let network: Network = { toServer, datagram in
                if toServer && datagram.ecn != .nonECT { datagram.ecn = rewritten }
                return true
            }
            var pair = Self.connectedPair(network: network)
            XCTAssertEqual(pair.client.ecn.state, .unsupported, "rewritten to \(rewritten)")
            // The server still validates its own marks.
            XCTAssertEqual(pair.server?.ecn.state, .probingValidated, "rewritten to \(rewritten)")
            var codepoints: [IPProtocol.ECN] = []
            try Self.send(
                5000,
                &pair,
                network: { toServer, datagram in
                    if toServer { codepoints.append(datagram.ecn) }
                    return network(toServer, &datagram)
                }
            )
            XCTAssertEqual(Set(codepoints), [.nonECT], "rewritten to \(rewritten)")
        }
    }

    /// RFC 9000 Section 13.4.2.1: counts that don't cover the newly acknowledged packets fail
    /// validation.
    func testAPathThatClearsSomeMarksMakesECNUnsupported() throws {
        var pair = Self.connectedPair()
        XCTAssertEqual(pair.client.ecn.state, .probingValidated)
        var marked = 0
        try Self.send(
            5000,
            &pair,
            network: { toServer, datagram in
                guard toServer, datagram.ecn != .nonECT else { return true }
                marked += 1
                if marked % 2 == 0 { datagram.ecn = .nonECT }
                return true
            }
        )
        XCTAssertGreaterThan(marked, 1)
        XCTAssertEqual(pair.client.ecn.state, .unsupported)
        // The server reported the marks that arrived.
        XCTAssertGreaterThan(pair.server?.acks[.applicationData].ecnCounts.ect0 ?? 0, 0)
    }

    func testAPathThatMarksEverythingCEIsMangling() throws {
        let network: Network = { toServer, datagram in
            if toServer && datagram.ecn == .ect0 { datagram.ecn = .ce }
            return true
        }
        var pair = Self.connectedPair(network: network)
        // CE alone can't tell yet; the counts add up.
        XCTAssertEqual(pair.client.ecn.state, .probingValidated)
        var codepoints: [IPProtocol.ECN] = []
        let streamID = try Self.send(
            20_000,
            &pair,
            network: { toServer, datagram in
                if toServer { codepoints.append(datagram.ecn) }
                return network(toServer, &datagram)
            }
        )
        XCTAssertEqual(Self.serverRead(streamID, &pair), 20_000)
        XCTAssertEqual(pair.client.ecn.state, .manglingDetected)
        XCTAssertEqual(codepoints.last, .nonECT)
        XCTAssertGreaterThan(pair.server?.statistics[.rxECTCE] ?? 0, 0)
        XCTAssertGreaterThan(pair.client.statistics[.ecnCapablePacketsMarked], 0)
        // CE marks before validation succeeded are no congestion signal.
        XCTAssertNil(pair.client.recovery.congestionRecoveryStartTime)
    }

    /// A path that drops ECN-capable packets: the validation packets are lost, and the ones
    /// without a mark arrive. Marking stops and the data gets through.
    func testLostValidationPacketsBlackholeThePath() throws {
        var pair = Self.connectedPair()
        // Validation starts over on the new path, which a middlebox guards.
        XCTAssertTrue(pair.client.probePath(Self.newPath, now: pair.now))
        pair.exchangeWithECN()
        XCTAssertTrue(pair.client.isPathValidated(Self.newPath))
        XCTAssertTrue(pair.client.migrate(to: Self.newPath, now: pair.now))
        XCTAssertEqual(pair.client.activePathID, Self.newPath)
        XCTAssertEqual(pair.client.ecn.state, .probing)

        // The server sends a response the client acknowledges, in ACK-only datagrams that go out
        // unmarked while the client probes.
        guard var server = pair.server.take() else { return XCTFail("No server") }
        let responseID = try XCTUnwrap(server.openStream(bidirectional: false))
        server.write([UInt8](repeating: 0x52, count: 60_000).span.bytes, to: responseID, fin: true)
        pair.server = consume server
        var dropped = 0
        let streamID = try Self.send(
            5000,
            &pair,
            network: { toServer, datagram in
                guard toServer, datagram.ecn != .nonECT else { return true }
                dropped += 1
                return false
            }
        )
        XCTAssertGreaterThanOrEqual(dropped, 3)
        XCTAssertEqual(pair.client.ecn.state, .blackholed)
        XCTAssertGreaterThanOrEqual(pair.client.ecn.validationPacketsLost, 3)
        XCTAssertGreaterThanOrEqual(pair.client.statistics[.ecnCapablePacketsLost], 3)
        XCTAssertEqual(Self.serverRead(streamID, &pair), 5000)
    }

    /// Until validation succeeded, a datagram without an ack-eliciting packet goes out unmarked:
    /// its loss would go unnoticed (RFC 9000 Section 13.4.2).
    func testACKOnlyDatagramsAreUnmarkedUntilValidated() throws {
        var pair = Self.connectedPair()
        XCTAssertEqual(pair.client.ecn.state, .probingValidated)
        let validationPackets = pair.client.ecn.validationPacketsSent
        guard var server = pair.server.take() else { return XCTFail("No server") }
        let streamID = try XCTUnwrap(server.openStream(bidirectional: false))
        server.write([UInt8](repeating: 0x53, count: 3000).span.bytes, to: streamID, fin: true)
        let fromServer = LockstepPair.drainWithECN(&server, now: pair.now)
        pair.server = consume server
        for var datagram in fromServer {
            let (path, ecn) = (datagram.path, datagram.ecn)
            var span = datagram.bytes.mutableSpan
            pair.client.receive(&span, on: path, ecn: ecn, now: pair.now)
        }
        let acknowledgements = LockstepPair.drainWithECN(&pair.client, now: pair.now)
        XCTAssertFalse(acknowledgements.isEmpty)
        XCTAssertEqual(acknowledgements.map(\.ecn), acknowledgements.map { _ in .nonECT })
        XCTAssertEqual(pair.client.ecn.validationPacketsSent, validationPackets)
    }

    // MARK: Congestion

    /// RFC 9000 Section 13.2.1: a packet marked CE is acknowledged right away.
    func testACEMarkedPacketIsAcknowledgedRightAway() throws {
        for codepoint in [IPProtocol.ECN.ect0, .ce] {
            var pair = Self.connectedPair()
            pair.exchangeWithECN()
            let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
            pair.client.write([UInt8]("one packet".utf8).span.bytes, to: streamID)
            let datagrams = LockstepPair.drainWithECN(&pair.client, now: pair.now)
            XCTAssertEqual(datagrams.count, 1)
            guard var server = pair.server.take() else { return XCTFail("No server") }
            for var datagram in datagrams {
                let path = datagram.path
                var span = datagram.bytes.mutableSpan
                server.receive(&span, on: path, ecn: codepoint, now: pair.now)
            }
            XCTAssertEqual(server.acks[.applicationData].ackNeeded, codepoint == .ce, "\(codepoint)")
            XCTAssertEqual(server.acks[.applicationData].ackDeadline != nil, codepoint != .ce, "\(codepoint)")
            pair.server = consume server
        }
    }

    /// RFC 9002 Section 7.1: CE marks reduce the window like a loss, once per recovery period.
    func testCongestionExperiencedReducesTheWindowOncePerRecoveryPeriod() throws {
        var pair = Self.connectedPair()
        try Self.send(20_000, &pair)
        XCTAssertEqual(pair.client.ecn.state, .capable)
        XCTAssertNil(pair.client.recovery.congestionRecoveryStartTime)

        let ceNetwork: Network = { toServer, datagram in
            if toServer && datagram.ecn == .ect0 { datagram.ecn = .ce }
            return true
        }
        let windowBefore = pair.client.recovery.congestionWindow
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x43, count: 8000).span.bytes, to: streamID, fin: true)
        let firstMark = pair.now
        // The server acknowledges each CE-marked datagram on its own, in an ACK frame each.
        let datagrams = LockstepPair.drainWithECN(&pair.client, now: pair.now)
        XCTAssertGreaterThan(datagrams.count, 2)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        var acknowledgements = 0
        for var datagram in datagrams {
            let path = datagram.path
            var span = datagram.bytes.mutableSpan
            server.receive(&span, on: path, ecn: .ce, now: pair.now)
            for var acknowledgement in LockstepPair.drainWithECN(&server, now: pair.now) {
                acknowledgements += 1
                let ecn = acknowledgement.ecn
                var span = acknowledgement.bytes.mutableSpan
                pair.client.receive(&span, on: path, ecn: ecn, now: pair.now)
            }
        }
        pair.server = consume server
        let markedFirst = pair.client.statistics[.ecnCapablePacketsMarked]
        XCTAssertEqual(markedFirst, datagrams.count)
        XCTAssertEqual(acknowledgements, datagrams.count, "an ACK frame per CE mark")
        XCTAssertEqual(pair.client.recovery.congestionRecoveryStartTime, firstMark)
        let threshold = pair.client.recovery.slowStartThreshold
        // One halving of a window that only grew before the first CE mark.
        XCTAssertGreaterThanOrEqual(threshold, windowBefore / 2)
        XCTAssertLessThan(threshold, windowBefore)
        XCTAssertEqual(pair.client.recovery.congestionWindow, threshold)

        // Marks on packets sent after the recovery period started count again.
        pair.now = pair.now.advanced(by: .milliseconds(50))
        let secondMark = pair.now
        pair.client.write(
            [UInt8](repeating: 0x43, count: 1).span.bytes,
            to: try XCTUnwrap(pair.client.openStream(bidirectional: true)),
            fin: true
        )
        pair.exchangeWithECN(network: ceNetwork)
        XCTAssertGreaterThan(pair.client.statistics[.ecnCapablePacketsMarked], markedFirst)
        XCTAssertEqual(pair.client.recovery.congestionRecoveryStartTime, secondMark)
        XCTAssertLessThan(pair.client.recovery.slowStartThreshold, threshold)
        XCTAssertEqual(pair.client.ecn.state, .capable)
    }

    // MARK: Migration

    /// RFC 9000 Section 13.4.2: ECN is validated on each path. The counts of the packet number
    /// space go on, which doesn't fail the new validation.
    func testValidationStartsOverOnANewPath() throws {
        var pair = Self.connectedPair()
        try Self.send(20_000, &pair)
        XCTAssertEqual(pair.client.ecn.state, .capable)

        XCTAssertTrue(pair.client.probePath(Self.newPath, now: pair.now))
        pair.exchangeWithECN()
        XCTAssertTrue(pair.client.migrate(to: Self.newPath, now: pair.now))
        XCTAssertEqual(pair.client.ecn.state, .probing)
        XCTAssertEqual(pair.client.ecn.validationPacketsSent, 0)

        let streamID = try Self.send(20_000, &pair)
        XCTAssertEqual(Self.serverRead(streamID, &pair), 20_000)
        XCTAssertEqual(pair.server?.activePathID, Self.newPath)
        XCTAssertEqual(pair.client.ecn.state, .capable)
        XCTAssertEqual(pair.server?.ecn.state.isMarking, true)
    }

    /// Validation packets of the old path that turn out lost after a migration don't count
    /// against the new path.
    func testLostValidationPacketsOfTheOldPathDoNotCountOnTheNewOne() throws {
        var pair = Self.connectedPair()
        XCTAssertTrue(pair.client.probePath(Self.newPath, now: pair.now))
        pair.exchangeWithECN()
        XCTAssertEqual(pair.client.ecn.state, .probingValidated)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 0x4f, count: 4000).span.bytes, to: streamID, fin: true)
        // They never arrive.
        let lost = LockstepPair.drainWithECN(&pair.client, now: pair.now)
        XCTAssertGreaterThanOrEqual(lost.filter { $0.ecn != .nonECT }.count, 3)
        XCTAssertTrue(pair.client.migrate(to: Self.newPath, now: pair.now))
        XCTAssertEqual(pair.client.ecn.state, .probing)

        try Self.send(1000, &pair)
        XCTAssertEqual(Self.serverRead(streamID, &pair), 4000)
        XCTAssertGreaterThanOrEqual(pair.client.statistics[.ecnCapablePacketsLost], 3)
        XCTAssertEqual(pair.client.ecn.validationPacketsLost, 0)
        XCTAssertTrue(pair.client.ecn.state.isMarking, "\(pair.client.ecn.state)")
    }

    // MARK: Pieces

    func testACKFrameCarriesTheCounts() {
        var tracker = CoreAckTracker()
        let now = NetworkClock.Instant(milliseconds: 1000)
        tracker.onPacketReceived(5, isAckEliciting: true, immediate: true, maxAckDelay: .milliseconds(25), now: now)
        var buffer = [UInt8](repeating: 0, count: 64)
        let cases = [
            (CoreECNCounts(), UInt8(0x02)),
            (CoreECNCounts(ect0: 1 << 20, ect1: 0, ce: 70), 0x03),
            // Counts in eight bytes each, which the length has to account for.
            (CoreECNCounts(ect0: 1 << 40, ect1: 1 << 40, ce: 1 << 40), 0x03),
        ]
        for (counts, type) in cases {
            tracker.ecnCounts = counts
            let length: Int
            do {
                var writer = CoreWriter(buffer.mutableSpan)
                XCTAssertEqual(tracker.writeAck(into: &writer, now: now, ackDelayExponent: 3), 5)
                length = writer.offset
            }
            XCTAssertEqual(buffer[0], type)
            XCTAssertLessThanOrEqual(length, tracker.ackFrameLength(now: now, ackDelayExponent: 3))
            if counts.ect0 == 1 << 20 {
                // The counts follow the single range: ECT(0) in four bytes, ECT(1), CE in two.
                XCTAssertEqual(length, 12)
                XCTAssertEqual(Array(buffer[5..<12]), [0x80, 0x10, 0x00, 0x00, 0x00, 0x40, 0x46])
            }
        }
    }

    func testReorderedACKFramesNeverFailValidation() {
        var validator = CoreECNValidator(markingEnabled: true, useECT1: false)
        _ = validator.mark(ackElicitingPackets: 1)
        var feedback = CoreECNCounts(ect0: 5, ect1: 0, ce: 0)
        // Neither missing counts on an ACK frame that doesn't raise the largest acknowledged…
        XCTAssertEqual(
            validator.validate(
                nil,
                newlyAcknowledged: 1,
                increasesLargestAcknowledged: false,
                sent: 6,
                feedback: &feedback
            ),
            0
        )
        XCTAssertEqual(validator.state, .probing)
        // … nor counts below the ones already reported.
        XCTAssertEqual(
            validator.validate(
                CoreECNCounts(ect0: 4, ect1: 0, ce: 0),
                newlyAcknowledged: 1,
                increasesLargestAcknowledged: true,
                sent: 6,
                feedback: &feedback
            ),
            0
        )
        XCTAssertEqual(validator.state, .probing)
        XCTAssertEqual(feedback, CoreECNCounts(ect0: 5, ect1: 0, ce: 0))
        // Counts that cover the newly acknowledged packets validate them.
        XCTAssertEqual(
            validator.validate(
                CoreECNCounts(ect0: 5, ect1: 0, ce: 1),
                newlyAcknowledged: 1,
                increasesLargestAcknowledged: true,
                sent: 6,
                feedback: &feedback
            ),
            1
        )
        XCTAssertEqual(validator.state, .probingValidated)
        // More ECT(0) and CE than went out marked is wrong.
        XCTAssertEqual(
            validator.validate(
                CoreECNCounts(ect0: 6, ect1: 0, ce: 1),
                newlyAcknowledged: 1,
                increasesLargestAcknowledged: true,
                sent: 6,
                feedback: &feedback
            ),
            0
        )
        XCTAssertEqual(validator.state, .unsupported)

        // Any count of ECT(1), which this endpoint never sets, fails it, even when ECT(0) covers
        // the newly acknowledged packets.
        var remarked = CoreECNValidator(markingEnabled: true, useECT1: false)
        _ = remarked.mark(ackElicitingPackets: 2)
        var remarkedFeedback = CoreECNCounts()
        XCTAssertEqual(
            remarked.validate(
                CoreECNCounts(ect0: 1, ect1: 1, ce: 0),
                newlyAcknowledged: 1,
                increasesLargestAcknowledged: true,
                sent: 2,
                feedback: &remarkedFeedback
            ),
            0
        )
        XCTAssertEqual(remarked.state, .unsupported)
    }
}

#endif
