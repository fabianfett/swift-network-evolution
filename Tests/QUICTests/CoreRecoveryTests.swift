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

/// `CoreRecovery` against a model that scans every sent packet on every ACK.
@available(Network 0.1.0, *)
final class CoreRecoveryTests: XCTestCase {
    private struct Generator: RandomNumberGenerator {
        var state: UInt64

        mutating func next() -> UInt64 {
            self.state &+= 0x9E37_79B9_7F4A_7C15
            var z = self.state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    /// The sent packets of one space, acknowledged and declared lost by scanning all of them.
    private struct Model {
        struct Packet {
            var number: UInt64
            var timeSent: NetworkClock.Instant
            var size: Int
        }

        var sent: [Packet] = []
        var largestAcknowledged: UInt64?
        var bytesInFlight = 0

        mutating func acknowledge(_ ranges: [ClosedRange<UInt64>]) -> [UInt64] {
            if let largest = ranges.first?.upperBound {
                self.largestAcknowledged = max(self.largestAcknowledged ?? largest, largest)
            }
            let acknowledged = self.sent.filter { packet in ranges.contains { $0.contains(packet.number) } }
            self.sent.removeAll { packet in ranges.contains { $0.contains(packet.number) } }
            self.bytesInFlight -= acknowledged.reduce(0) { $0 + $1.size }
            return acknowledged.map(\.number)
        }

        mutating func detectLost(now: NetworkClock.Instant, lossDelay: NetworkDuration) -> [UInt64] {
            guard let largest = self.largestAcknowledged else { return [] }
            let lost = self.sent.filter { packet in
                packet.number <= largest
                    && (packet.timeSent.advanced(by: lossDelay) <= now || largest >= packet.number + 3)
            }
            self.sent.removeAll { packet in lost.contains { $0.number == packet.number } }
            self.bytesInFlight -= lost.reduce(0) { $0 + $1.size }
            return lost.map(\.number)
        }
    }

    /// Random ACK frames over a window of sent packets, with gaps, repeats and numbers never sent.
    private static func ranges(
        upTo largest: UInt64,
        using generator: inout Generator
    ) -> [ClosedRange<UInt64>] {
        var ranges: [ClosedRange<UInt64>] = []
        var upper = largest
        for _ in 0..<Int.random(in: 1...4, using: &generator) {
            let length = UInt64.random(in: 0...6, using: &generator)
            let lower = upper >= length ? upper - length : 0
            ranges.append(lower...upper)
            let gap = UInt64.random(in: 2...8, using: &generator)
            guard lower >= gap else { break }
            upper = lower - gap
        }
        return ranges
    }

    func testAcknowledgementsAndLossesMatchAFullScan() {
        for seed in UInt64(1)...200 {
            var generator = Generator(state: seed)
            var recovery = CoreRecovery()
            var model = Model()
            var now = NetworkClock.Instant(milliseconds: 1_000)
            var nextPacketNumber: UInt64 = 0
            for round in 0..<60 {
                for _ in 0..<Int.random(in: 0...12, using: &generator) {
                    // Skipped packet numbers are allowed (RFC 9000 Section 12.3).
                    nextPacketNumber += UInt64.random(in: 0...1, using: &generator) == 0 ? 1 : 2
                    let size = Int.random(in: 50...1350, using: &generator)
                    recovery.onPacketSent(
                        CoreSentPacket(
                            packetNumber: nextPacketNumber,
                            timeSent: now,
                            size: size,
                            isAckEliciting: true,
                            isInFlight: true,
                            frames: [.ping]
                        ),
                        in: .applicationData
                    )
                    model.sent.append(Model.Packet(number: nextPacketNumber, timeSent: now, size: size))
                    model.bytesInFlight += size
                }
                now = now.advanced(by: .milliseconds(Int64.random(in: 0...40, using: &generator)))
                guard nextPacketNumber > 0, Bool.random(using: &generator) else { continue }
                let largest = UInt64.random(in: (nextPacketNumber / 2)...nextPacketNumber, using: &generator)
                let ranges = Self.ranges(upTo: largest, using: &generator)

                // The model needs the loss delay as of after this ACK's RTT sample.
                let result = recovery.onAckReceived(
                    ranges: ranges,
                    ackDelay: .zero,
                    in: .applicationData,
                    handshakeConfirmed: true,
                    now: now
                )
                let lossDelay = max(
                    max(recovery.latestRTT, recovery.smoothedRTT) + max(recovery.latestRTT, recovery.smoothedRTT) / 8,
                    .milliseconds(1)
                )
                let acknowledged = model.acknowledge(ranges)
                let lost = acknowledged.isEmpty ? [] : model.detectLost(now: now, lossDelay: lossDelay)

                let context = "seed \(seed), round \(round), ranges \(ranges)"
                XCTAssertEqual(result.acknowledged.map(\.packetNumber), acknowledged, context)
                XCTAssertEqual(result.lost.map(\.packetNumber), lost, context)
                XCTAssertEqual(
                    recovery.spaces[2].sent.map(\.packetNumber),
                    model.sent.map(\.number),
                    context
                )
                XCTAssertEqual(recovery.bytesInFlight, model.bytesInFlight, context)
                XCTAssertEqual(recovery.spaces[2].ackElicitingInFlight, model.sent.count, context)
            }
        }
    }

    // MARK: RTT estimation (RFC 9002 Section 5)

    private static func sendPacket(
        _ recovery: inout CoreRecovery,
        _ packetNumber: UInt64,
        at time: NetworkClock.Instant,
        isAckEliciting: Bool = true,
        in space: PacketNumberSpace = .applicationData
    ) {
        recovery.onPacketSent(
            CoreSentPacket(
                packetNumber: packetNumber,
                timeSent: time,
                size: 1000,
                isAckEliciting: isAckEliciting,
                isInFlight: true,
                frames: isAckEliciting ? [.ping] : []
            ),
            in: space
        )
    }

    /// Sends packet `packetNumber` at `sent`, and acknowledges it alone at `sent + rtt`.
    private static func sample(
        _ recovery: inout CoreRecovery,
        _ packetNumber: UInt64,
        rtt: NetworkDuration,
        ackDelay: NetworkDuration = .zero,
        handshakeConfirmed: Bool = true,
        sent: NetworkClock.Instant
    ) -> CoreRecovery.AckResult {
        Self.sendPacket(&recovery, packetNumber, at: sent)
        return recovery.onAckReceived(
            ranges: [packetNumber...packetNumber],
            ackDelay: ackDelay,
            in: .applicationData,
            handshakeConfirmed: handshakeConfirmed,
            now: sent.advanced(by: rtt)
        )
    }

    /// RFC 9002 Section 5.3: the first sample sets the smoothed RTT and half of it the variation;
    /// Section 5.2: it is the minimum RTT.
    func testTheFirstSampleInitializesTheEstimate() {
        var recovery = CoreRecovery()
        XCTAssertEqual(recovery.smoothedRTT, CoreRecovery.initialRTT)
        // The first sample ignores the ACK delay.
        let result = Self.sample(
            &recovery,
            0,
            rtt: .milliseconds(100),
            ackDelay: .milliseconds(10),
            sent: NetworkClock.Instant(milliseconds: 1_000)
        )
        XCTAssertTrue(result.rttSampled)
        XCTAssertEqual(recovery.latestRTT, .milliseconds(100))
        XCTAssertEqual(recovery.smoothedRTT, .milliseconds(100))
        XCTAssertEqual(recovery.rttVariance, .milliseconds(50))
        XCTAssertEqual(recovery.minRTT, .milliseconds(100))
    }

    /// RFC 9002 Section 5.3: later samples are smoothed after subtracting the ACK delay, unless
    /// that would go below the minimum RTT; after the handshake is confirmed the delay is capped
    /// at the peer's max_ack_delay. The minimum RTT ignores the ACK delay (Section 5.2).
    func testLaterSamplesSubtractTheAckDelayAndAreSmoothed() {
        var recovery = CoreRecovery()
        recovery.maxAckDelay = .milliseconds(25)
        var now = NetworkClock.Instant(milliseconds: 1_000)
        _ = Self.sample(&recovery, 0, rtt: .milliseconds(100), sent: now)

        // 140 ms minus 20 ms of ACK delay.
        now = now.advanced(by: .milliseconds(200))
        _ = Self.sample(&recovery, 1, rtt: .milliseconds(140), ackDelay: .milliseconds(20), sent: now)
        XCTAssertEqual(recovery.latestRTT, .milliseconds(140))
        XCTAssertEqual(recovery.minRTT, .milliseconds(100))
        XCTAssertEqual(recovery.smoothedRTT, .microseconds(102_500))
        XCTAssertEqual(recovery.rttVariance, .microseconds(42_500))

        // Subtracting the ACK delay, capped at 25 ms, would go below the minimum RTT: the sample
        // stays 110 ms.
        let smoothed = recovery.smoothedRTT
        now = now.advanced(by: .milliseconds(200))
        _ = Self.sample(&recovery, 2, rtt: .milliseconds(110), ackDelay: .milliseconds(50), sent: now)
        XCTAssertEqual(recovery.smoothedRTT, (smoothed * 7) / 8 + .milliseconds(110) / 8)

        // After the handshake is confirmed, 100 ms of ACK delay count as max_ack_delay.
        var capped = CoreRecovery()
        capped.maxAckDelay = .milliseconds(25)
        now = now.advanced(by: .milliseconds(200))
        _ = Self.sample(&capped, 0, rtt: .milliseconds(100), sent: now)
        now = now.advanced(by: .milliseconds(200))
        _ = Self.sample(&capped, 1, rtt: .milliseconds(225), ackDelay: .milliseconds(100), sent: now)
        XCTAssertEqual(capped.smoothedRTT, (.milliseconds(100) * 7) / 8 + .milliseconds(200) / 8)

        // Before, all of it counts.
        var uncapped = CoreRecovery()
        uncapped.maxAckDelay = .milliseconds(25)
        now = now.advanced(by: .milliseconds(200))
        _ = Self.sample(&uncapped, 0, rtt: .milliseconds(100), sent: now)
        now = now.advanced(by: .milliseconds(200))
        _ = Self.sample(
            &uncapped,
            1,
            rtt: .milliseconds(225),
            ackDelay: .milliseconds(100),
            handshakeConfirmed: false,
            sent: now
        )
        XCTAssertEqual(uncapped.smoothedRTT, (.milliseconds(100) * 7) / 8 + .milliseconds(125) / 8)
    }

    /// RFC 9002 Section 5.1: an ACK frame is an RTT sample if it newly acknowledges the largest
    /// packet number, and at least one of the packets it newly acknowledges is ack-eliciting.
    func testOnlyAnAckOfANewLargestWithAnAckElicitingPacketIsASample() {
        var recovery = CoreRecovery()
        let start = NetworkClock.Instant(milliseconds: 1_000)
        Self.sendPacket(&recovery, 0, at: start, isAckEliciting: false)
        var result = recovery.onAckReceived(
            ranges: [0...0],
            ackDelay: .zero,
            in: .applicationData,
            handshakeConfirmed: true,
            now: start.advanced(by: .milliseconds(50))
        )
        XCTAssertFalse(result.rttSampled, "Nothing ack-eliciting was acknowledged")
        XCTAssertEqual(result.acknowledged.count, 1)

        Self.sendPacket(&recovery, 1, at: start)
        Self.sendPacket(&recovery, 2, at: start, isAckEliciting: false)
        result = recovery.onAckReceived(
            ranges: [1...2],
            ackDelay: .zero,
            in: .applicationData,
            handshakeConfirmed: true,
            now: start.advanced(by: .milliseconds(80))
        )
        XCTAssertTrue(result.rttSampled)
        XCTAssertEqual(recovery.latestRTT, .milliseconds(80))

        // The same ACK frame again acknowledges nothing new.
        result = recovery.onAckReceived(
            ranges: [0...2],
            ackDelay: .zero,
            in: .applicationData,
            handshakeConfirmed: true,
            now: start.advanced(by: .milliseconds(300))
        )
        XCTAssertFalse(result.rttSampled)
        XCTAssertEqual(recovery.latestRTT, .milliseconds(80))
    }

    // MARK: Probe timeout (RFC 9002 Section 6.2)

    /// The PTO is smoothed_rtt + max(4 * rttvar, granularity), plus max_ack_delay in the
    /// application data space, doubled for every PTO in a row (Section 6.2.1).
    func testTheProbeTimeoutBacksOffExponentially() {
        var recovery = CoreRecovery()
        recovery.maxAckDelay = .milliseconds(25)
        let start = NetworkClock.Instant(milliseconds: 1_000)
        _ = Self.sample(&recovery, 0, rtt: .milliseconds(100), sent: start)
        let pto = NetworkDuration.milliseconds(100 + 4 * 50 + 25)
        XCTAssertEqual(recovery.probeTimeout(includingMaxAckDelay: true), pto)
        XCTAssertEqual(recovery.probeTimeout(includingMaxAckDelay: false), pto - .milliseconds(25))

        let sent = start.advanced(by: .milliseconds(200))
        Self.sendPacket(&recovery, 1, at: sent)
        for backoff in [1, 2, 4] {
            let deadline = recovery.lossDetectionDeadline(
                handshakeConfirmed: true,
                hasHandshakeKeys: true,
                peerAwaitingAddressValidation: false
            )
            XCTAssertEqual(deadline?.deadline, sent.advanced(by: pto * backoff))
            XCTAssertEqual(deadline?.space, .applicationData)
            guard
                case .probe(.applicationData) = recovery.onLossDetectionTimeout(
                    handshakeConfirmed: true,
                    hasHandshakeKeys: true,
                    peerAwaitingAddressValidation: false,
                    now: sent.advanced(by: pto * backoff)
                )
            else {
                return XCTFail("No probe")
            }
        }
        // An acknowledgement resets the backoff.
        _ = recovery.onAckReceived(
            ranges: [1...1],
            ackDelay: .zero,
            in: .applicationData,
            handshakeConfirmed: true,
            now: sent.advanced(by: .seconds(5))
        )
        XCTAssertEqual(recovery.ptoCount, 0)
    }

    /// RFC 9002 Section 6.2.1: application data probes wait until the handshake is confirmed.
    func testApplicationDataProbesWaitForTheConfirmedHandshake() {
        var recovery = CoreRecovery()
        let start = NetworkClock.Instant(milliseconds: 1_000)
        Self.sendPacket(&recovery, 0, at: start)
        XCTAssertNil(
            recovery.lossDetectionDeadline(
                handshakeConfirmed: false,
                hasHandshakeKeys: true,
                peerAwaitingAddressValidation: false
            )
        )
        Self.sendPacket(&recovery, 0, at: start, in: .handshake)
        XCTAssertEqual(
            recovery.lossDetectionDeadline(
                handshakeConfirmed: false,
                hasHandshakeKeys: true,
                peerAwaitingAddressValidation: false
            )?.space,
            .handshake
        )
    }

    /// RFC 9002 Section 6.4: discarding the keys of a space removes its packets from the bytes in
    /// flight and resets the backoff.
    func testDiscardingASpaceForgetsItsPacketsInFlight() {
        var recovery = CoreRecovery()
        let start = NetworkClock.Instant(milliseconds: 1_000)
        Self.sendPacket(&recovery, 0, at: start, in: .initial)
        Self.sendPacket(&recovery, 1, at: start, in: .initial)
        Self.sendPacket(&recovery, 0, at: start, in: .handshake)
        recovery.ptoCount = 2
        XCTAssertEqual(recovery.bytesInFlight, 3000)
        recovery.discard(.initial)
        XCTAssertEqual(recovery.bytesInFlight, 1000)
        XCTAssertEqual(recovery.ptoCount, 0)
        XCTAssertTrue(recovery.spaces[0].sent.isEmpty)
        XCTAssertTrue(recovery.hasAckElicitingInFlight)
    }
}

#endif
