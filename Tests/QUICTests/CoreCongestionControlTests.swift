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

/// Drives one congestion controller as `CoreRecovery` does: packets sent, an ACK frame's
/// acknowledgements, losses and ECN feedback, then the end of the ACK frame.
@available(Network 0.1.0, *)
private struct Driver<Controller: CoreCongestionControllerProtocol> {
    var state = CoreCongestionState(maxDatagramSize: 1200)
    var controller: Controller
    var smoothedRTT = NetworkDuration.zero

    init() {
        self.controller = Controller(state: &self.state)
    }

    var available: Int { max(0, self.state.congestionWindow - self.state.bytesInFlight) }

    mutating func send(_ count: Int, bytes: Int = 1000) {
        self.state.bytesInFlight += count * bytes
    }

    /// Starts an ACK frame that acknowledges `count` packets of `bytes` sent at `sentTime`.
    mutating func acknowledge(_ count: Int, bytes: Int = 1000, sentTime: NetworkClock.Instant) {
        self.state.bytesAcknowledged = 0
        for _ in 0..<count {
            self.state.bytesInFlight -= bytes
            if !self.state.inRecovery(sentTime: sentTime) {
                self.state.bytesAcknowledged += bytes
            }
        }
    }

    @discardableResult
    mutating func lose(bytes: Int = 1000, sentTime: NetworkClock.Instant, now: NetworkClock.Instant) -> Bool {
        self.state.bytesInFlight -= bytes
        return self.controller.onCongestionEvent(state: &self.state, sentTime: sentTime, now: now)
    }

    mutating func ecn(
        newlyCE: UInt64,
        newlyAcknowledged: UInt64,
        largestAcknowledged: UInt64,
        largestSent: UInt64,
        sentTime: NetworkClock.Instant,
        now: NetworkClock.Instant
    ) {
        self.controller.onECNFeedback(
            state: &self.state,
            CoreECNFeedback(
                newlyCE: newlyCE,
                newlyAcknowledged: newlyAcknowledged,
                largestAcknowledged: largestAcknowledged,
                largestSent: largestSent,
                largestAcknowledgedSentTime: sentTime
            ),
            smoothedRTT: self.smoothedRTT,
            now: now
        )
    }

    mutating func endAck(packetsLost: Bool = false, now: NetworkClock.Instant) {
        self.controller.onAckEnd(state: &self.state, packetsLost: packetsLost, smoothedRTT: self.smoothedRTT, now: now)
        self.state.bytesAcknowledged = 0
    }
}

/// The congestion controllers of `QUICConnectionCore`, with the expectations of `CubicTests` and
/// `PragueTests` for the classes' controllers, and persistent congestion (RFC 9002 Section 7.6).
@available(Network 0.1.0, *)
final class CoreCongestionControlTests: XCTestCase {
    private let t0 = NetworkClock.Instant(milliseconds: 1_000)

    // MARK: CUBIC

    func testCubicStartsWithTheInitialWindowAndGrowsInSlowStart() {
        var cubic = Driver<CoreCubic>()
        XCTAssertEqual(cubic.available, 12000)
        cubic.send(1)
        cubic.acknowledge(1, sentTime: self.t0)
        cubic.endAck(now: self.t0)
        XCTAssertEqual(cubic.available, 13000)
    }

    func testCubicReducesTheWindowByBetaOnLoss() {
        var cubic = Driver<CoreCubic>()
        cubic.send(1)
        XCTAssertTrue(cubic.lose(sentTime: self.t0, now: self.t0))
        XCTAssertEqual(cubic.available, 8400)
        XCTAssertEqual(cubic.state.slowStartThreshold, 8400)
    }

    func testCubicLeavesSlowStartAfterALoss() {
        var cubic = Driver<CoreCubic>()
        cubic.send(6)
        cubic.acknowledge(5, sentTime: self.t0)
        cubic.endAck(now: self.t0)
        cubic.lose(sentTime: self.t0, now: self.t0)
        // 17000 · 0.7.
        XCTAssertEqual(cubic.available, 11900)
        // Congestion avoidance from here: the Reno-friendly window grows by 3(1-β)/(1+β) per RTT.
        let later = self.t0.advanced(by: .microseconds(100))
        cubic.send(1)
        cubic.acknowledge(1, sentTime: later)
        cubic.endAck(now: later)
        XCTAssertEqual(cubic.available, 11953)
    }

    func testCubicTreatsCEMarksLikeALossOncePerRound() {
        var cubic = Driver<CoreCubic>()
        cubic.send(6)
        cubic.acknowledge(4, sentTime: self.t0)
        cubic.ecn(
            newlyCE: 1,
            newlyAcknowledged: 4,
            largestAcknowledged: 3,
            largestSent: 5,
            sentTime: self.t0,
            now: self.t0
        )
        cubic.endAck(now: self.t0)
        // 12000 · 0.7, and no growth for the ACK frame with the marks.
        XCTAssertEqual(cubic.state.congestionWindow, 8400)
        XCTAssertEqual(cubic.available, 6400)

        // More marks for packets of the same round don't reduce it again.
        let later = self.t0.advanced(by: .microseconds(100))
        cubic.acknowledge(2, sentTime: later)
        cubic.ecn(newlyCE: 1, newlyAcknowledged: 2, largestAcknowledged: 5, largestSent: 5, sentTime: later, now: later)
        cubic.endAck(now: later)
        XCTAssertEqual(cubic.available, 8400)

        // Marks of the next round do.
        let next = later.advanced(by: .milliseconds(1))
        cubic.send(1)
        cubic.acknowledge(1, sentTime: next)
        cubic.ecn(newlyCE: 1, newlyAcknowledged: 1, largestAcknowledged: 6, largestSent: 6, sentTime: next, now: next)
        cubic.endAck(now: next)
        XCTAssertEqual(cubic.state.congestionWindow, 5880)
    }

    func testCubicDoesntGrowForPacketsSentBeforeTheRecoveryPeriod() {
        var cubic = Driver<CoreCubic>()
        cubic.send(6)
        cubic.acknowledge(5, sentTime: self.t0)
        cubic.lose(sentTime: self.t0, now: self.t0)
        cubic.endAck(packetsLost: true, now: self.t0)
        XCTAssertEqual(cubic.available, 8400)
        let later = self.t0.advanced(by: .microseconds(100))
        cubic.send(1)
        cubic.acknowledge(1, sentTime: later)
        cubic.endAck(now: later)
        XCTAssertEqual(cubic.available, 8475)
    }

    func testCubicReducesOncePerRecoveryPeriod() {
        var cubic = Driver<CoreCubic>()
        var sentTime = self.t0
        var detectedAt = sentTime.advanced(by: .microseconds(100))
        cubic.send(6)
        cubic.acknowledge(5, sentTime: sentTime)
        cubic.lose(sentTime: sentTime, now: detectedAt)
        XCTAssertEqual(cubic.available, 8400)
        sentTime = sentTime.advanced(by: .microseconds(1000))
        detectedAt = sentTime.advanced(by: .microseconds(100))
        cubic.send(4)
        XCTAssertTrue(cubic.lose(sentTime: sentTime, now: detectedAt))
        for _ in 0..<3 {
            XCTAssertFalse(cubic.lose(sentTime: sentTime, now: detectedAt), "the same recovery period")
        }
        sentTime = sentTime.advanced(by: .microseconds(1000))
        detectedAt = sentTime.advanced(by: .microseconds(100))
        cubic.send(2)
        cubic.lose(sentTime: sentTime, now: detectedAt)
        cubic.lose(sentTime: sentTime, now: detectedAt)
        // 12000 -> 8400 -> 5880 -> 4116, each reduction truncated on its own.
        XCTAssertEqual(cubic.available, 4116)
    }

    func testCubicGrowsInCongestionAvoidanceWithoutALoss() {
        var cubic = Driver<CoreCubic>()
        cubic.state.slowStartThreshold = 12000
        cubic.send(12)
        cubic.acknowledge(12, sentTime: self.t0)
        cubic.endAck(now: self.t0)
        // Reno's α of 1 applies at W_max: a datagram per window acknowledged. W_max follows the
        // window before the first loss.
        XCTAssertEqual(cubic.state.congestionWindow, 13200)
        XCTAssertEqual(cubic.controller.maxWindow, 13200)
    }

    func testCubicFollowsTheCubicCurveBackToTheWindowBeforeTheLoss() {
        var cubic = Driver<CoreCubic>()
        cubic.smoothedRTT = .milliseconds(100)
        cubic.state.congestionWindow = 120_000
        cubic.state.slowStartThreshold = 120_000
        cubic.controller.maxWindow = 120_000
        cubic.lose(bytes: 0, sentTime: self.t0, now: self.t0)
        XCTAssertEqual(cubic.state.congestionWindow, 84000)
        // K = ∛(W_max (1-β) / C) in datagrams: ∛(36000 / 1200 / 0.4) = ∛75.
        XCTAssertEqual(cubic.controller.k, 4.2172, accuracy: 1e-4)
        // After K seconds the window is back at W_max.
        var now = self.t0
        let step = NetworkDuration.milliseconds(100)
        while cubic.state.congestionWindow < 120_000 && now < self.t0.advanced(by: .seconds(10)) {
            now = now.advanced(by: step)
            cubic.state.bytesInFlight = cubic.state.congestionWindow
            cubic.acknowledge(cubic.state.congestionWindow / 1200, bytes: 1200, sentTime: now)
            cubic.endAck(now: now)
        }
        let seconds = Double(self.t0.duration(to: now).nanoseconds) / 1e9
        XCTAssertEqual(seconds, 4.2172, accuracy: 0.25, "back at W_max after about K")
    }

    func testCubicFastConvergenceLowersTheMaximum() {
        var cubic = Driver<CoreCubic>()
        cubic.state.congestionWindow = 100_000
        cubic.lose(bytes: 0, sentTime: self.t0, now: self.t0)
        XCTAssertEqual(cubic.controller.maxWindow, 100_000)
        // A second loss below W_max releases bandwidth: W_max · (1 + β) / 2.
        let later = self.t0.advanced(by: .milliseconds(10))
        cubic.lose(bytes: 0, sentTime: later, now: later)
        XCTAssertEqual(cubic.controller.maxWindow, 59500)
        XCTAssertEqual(cubic.state.congestionWindow, 49000)
    }

    func testCubicDoesntGrowAWindowItDoesntUse() {
        var cubic = Driver<CoreCubic>()
        cubic.smoothedRTT = .milliseconds(10)
        cubic.state.congestionWindow = 100_000
        // A few RTTs of 2400 bytes each: far below the window.
        var now = self.t0
        for _ in 0..<5 {
            now = now.advanced(by: .milliseconds(11))
            cubic.send(2, bytes: 1200)
            cubic.acknowledge(2, bytes: 1200, sentTime: now)
            cubic.endAck(now: now)
        }
        XCTAssertEqual(cubic.controller.pipeAck.value, 2400)
        XCTAssertEqual(cubic.state.congestionWindow, 100_000 + 2400, "only the first ACK grew it")
        // A loss reduces what was in flight, not the unused window.
        cubic.send(2, bytes: 1200)
        cubic.lose(bytes: 0, sentTime: now, now: now)
        // β · 2400 is below the minimum window.
        XCTAssertEqual(cubic.state.congestionWindow, 2400)
    }

    func testCubicPersistentCongestionCollapsesTheWindow() {
        var cubic = Driver<CoreCubic>()
        cubic.send(4)
        cubic.controller.onPersistentCongestion(state: &cubic.state)
        XCTAssertEqual(cubic.state.congestionWindow, 2400)
        XCTAssertEqual(cubic.available, 0)
        XCTAssertEqual(cubic.state.slowStartThreshold, 8400)
    }

    // MARK: Prague

    func testPragueGrowsAndReactsToLossesLikeCubic() {
        var prague = Driver<CorePrague>()
        XCTAssertEqual(prague.available, 12000)
        prague.send(6)
        prague.acknowledge(5, sentTime: self.t0)
        prague.endAck(now: self.t0)
        prague.lose(sentTime: self.t0, now: self.t0)
        XCTAssertEqual(prague.available, 11900)
        let later = self.t0.advanced(by: .microseconds(100))
        prague.send(1)
        prague.acknowledge(1, sentTime: later)
        prague.endAck(now: later)
        XCTAssertEqual(prague.available, 11953)
    }

    func testPragueReducesByHalfAlphaOnCEMarks() {
        var prague = Driver<CorePrague>()
        prague.smoothedRTT = .milliseconds(15)
        prague.send(6)
        prague.acknowledge(6, sentTime: self.t0)
        prague.ecn(
            newlyCE: 1,
            newlyAcknowledged: 6,
            largestAcknowledged: 5,
            largestSent: 5,
            sentTime: self.t0,
            now: self.t0
        )
        // α = 15/16 + 1/16 · 1/6 of a window of 12000 halved is 5687: 6313. The 5 unmarked
        // packets grow it by (15 ms / 20 ms)² per RTT: 6826.
        XCTAssertEqual(prague.state.congestionWindow, 6313)
        prague.endAck(now: self.t0)
        XCTAssertEqual(prague.available, 6826)

        let later = self.t0.advanced(by: .microseconds(100))
        prague.send(1)
        prague.acknowledge(1, sentTime: later)
        prague.endAck(now: later)
        XCTAssertEqual(prague.available, 6924)
    }

    func testPragueReducesOncePerRoundAndCountsMarksForAlpha() {
        var prague = Driver<CorePrague>()
        prague.smoothedRTT = .milliseconds(15)
        prague.send(6)
        prague.acknowledge(4, sentTime: self.t0)
        prague.ecn(
            newlyCE: 1,
            newlyAcknowledged: 4,
            largestAcknowledged: 3,
            largestSent: 5,
            sentTime: self.t0,
            now: self.t0
        )
        prague.endAck(now: self.t0)
        // 12000 less α/2 with α from 1 of 4 marked: 6282, grown for 3 unmarked: 6582.
        XCTAssertEqual(prague.available, 4582)
        let alpha = prague.controller.alpha
        let scaledAlpha = prague.controller.scaledAlpha

        prague.acknowledge(2, sentTime: self.t0)
        prague.ecn(
            newlyCE: 1,
            newlyAcknowledged: 2,
            largestAcknowledged: 5,
            largestSent: 5,
            sentTime: self.t0,
            now: self.t0
        )
        prague.endAck(now: self.t0)
        // The same round: no reduction, α waits for the round to end; one unmarked packet grows.
        XCTAssertEqual(prague.available, 6664)
        XCTAssertEqual(prague.controller.alpha, alpha)

        // The next round: α moves towards the 1 mark of the 3 packets of the round.
        let later = self.t0.advanced(by: .milliseconds(15))
        prague.send(1)
        prague.acknowledge(1, sentTime: later)
        prague.ecn(
            newlyCE: 0,
            newlyAcknowledged: 1,
            largestAcknowledged: 6,
            largestSent: 6,
            sentTime: later,
            now: later
        )
        prague.endAck(now: later)
        XCTAssertEqual(prague.controller.alpha, (scaledAlpha - (scaledAlpha >> 4) + (1 << 20) / 3) >> 4)
    }

    func testPragueAlphaDecaysWithoutMarks() {
        var prague = Driver<CorePrague>()
        XCTAssertEqual(prague.controller.alpha, CorePrague.maxAlpha)
        for round in UInt64(0)..<16 {
            prague.ecn(
                newlyCE: 0,
                newlyAcknowledged: 10,
                largestAcknowledged: round * 10 + 9,
                largestSent: round * 10 + 9,
                sentTime: self.t0,
                now: self.t0
            )
        }
        // (15/16)^16 of one.
        XCTAssertLessThan(prague.controller.alpha, CorePrague.maxAlpha * 36 / 100)
        XCTAssertGreaterThan(prague.controller.alpha, CorePrague.maxAlpha * 35 / 100)
    }

    func testPragueReducesOncePerRecoveryPeriodForLosses() {
        var prague = Driver<CorePrague>()
        var sentTime = self.t0
        prague.send(6)
        prague.acknowledge(5, sentTime: sentTime)
        prague.lose(sentTime: sentTime, now: sentTime.advanced(by: .microseconds(100)))
        sentTime = sentTime.advanced(by: .microseconds(1000))
        prague.send(4)
        XCTAssertTrue(prague.lose(sentTime: sentTime, now: sentTime.advanced(by: .microseconds(100))))
        for _ in 0..<3 {
            XCTAssertFalse(prague.lose(sentTime: sentTime, now: sentTime.advanced(by: .microseconds(100))))
        }
        sentTime = sentTime.advanced(by: .microseconds(1000))
        prague.send(2)
        prague.lose(sentTime: sentTime, now: sentTime.advanced(by: .microseconds(100)))
        prague.lose(sentTime: sentTime, now: sentTime.advanced(by: .microseconds(100)))
        XCTAssertEqual(prague.available, 4116)
        XCTAssertFalse(prague.controller.reducedForCE)
    }

    func testPraguePersistentCongestionCollapsesTheWindow() {
        var prague = Driver<CorePrague>()
        prague.send(4)
        prague.controller.onPersistentCongestion(state: &prague.state)
        XCTAssertEqual(prague.available, 0)
        XCTAssertEqual(prague.state.congestionWindow, 2400)
    }

    func testPraguePacesInShorterBursts() {
        var recovery = CoreRecovery(congestionControl: .prague)
        XCTAssertEqual(recovery.controller.burstShift, 12)
        XCTAssertEqual(CoreRecovery(congestionControl: .cubic).controller.burstShift, 10)
        recovery.pacer = CorePacer()
        recovery.onAckEnd(packetsLost: false, now: self.t0)
        let rate = recovery.pacer?.rate ?? 0
        XCTAssertGreaterThan(rate, 0)
        XCTAssertEqual(recovery.pacer?.burstSize, Int(rate >> 12))
    }

    // MARK: NewReno

    func testNewRenoHalvesTheWindow() {
        var newReno = Driver<CoreNewReno>()
        newReno.send(1)
        newReno.lose(sentTime: self.t0, now: self.t0)
        XCTAssertEqual(newReno.state.congestionWindow, 6000)
        newReno.ecn(
            newlyCE: 1,
            newlyAcknowledged: 1,
            largestAcknowledged: 1,
            largestSent: 1,
            sentTime: self.t0,
            now: self.t0
        )
        XCTAssertEqual(newReno.state.congestionWindow, 6000, "the same recovery period")
    }

    func testNewRenoDoesntGrowAWindowItDoesntUse() {
        var newReno = Driver<CoreNewReno>()
        newReno.smoothedRTT = .milliseconds(10)
        newReno.state.congestionWindow = 100_000
        // A few RTTs of 2400 bytes each: far below the window (RFC 9002 Section 7.8).
        var now = self.t0
        for _ in 0..<5 {
            now = now.advanced(by: .milliseconds(11))
            newReno.send(2, bytes: 1200)
            newReno.acknowledge(2, bytes: 1200, sentTime: now)
            newReno.endAck(now: now)
        }
        XCTAssertEqual(newReno.controller.pipeAck.value, 2400)
        XCTAssertEqual(newReno.state.congestionWindow, 100_000 + 2400, "only the first ACK grew it")
        // A window that is used grows again.
        for _ in 0..<3 {
            now = now.advanced(by: .milliseconds(11))
            newReno.send(50, bytes: 1200)
            newReno.acknowledge(50, bytes: 1200, sentTime: now)
            newReno.endAck(now: now)
        }
        XCTAssertGreaterThan(newReno.state.congestionWindow, 100_000 + 2400)
    }

    // MARK: Persistent congestion

    private static func packet(_ number: UInt64, at time: NetworkClock.Instant, probe: Bool = false) -> CoreSentPacket {
        CoreSentPacket(
            packetNumber: number,
            timeSent: time,
            size: 1200,
            isAckEliciting: true,
            isInFlight: true,
            frames: probe ? [.pmtudProbe(size: 1200)] : [.ping]
        )
    }

    /// A recovery with an RTT sample of 10 ms at 10 ms, and packets 1 to 3 sent at `times`.
    private func recovery(
        _ algorithm: CoreCongestionControlAlgorithm = .newReno,
        sending times: [Int64],
        probes: Bool = false
    ) -> CoreRecovery {
        var recovery = CoreRecovery(congestionControl: algorithm)
        recovery.onPacketSent(Self.packet(0, at: self.t0), in: .applicationData)
        _ = recovery.onAckReceived(
            ranges: [0...0],
            ackDelay: .zero,
            in: .applicationData,
            handshakeConfirmed: true,
            now: self.t0.advanced(by: .milliseconds(10))
        )
        recovery.onAckEnd(packetsLost: false, now: self.t0.advanced(by: .milliseconds(10)))
        for (index, time) in times.enumerated() {
            recovery.onPacketSent(
                Self.packet(UInt64(index + 1), at: self.t0.advanced(by: .milliseconds(time)), probe: probes),
                in: .applicationData
            )
        }
        return recovery
    }

    private func acknowledge(
        _ ranges: [ClosedRange<UInt64>],
        at time: Int64,
        _ recovery: inout CoreRecovery
    )
        -> CoreRecovery.AckResult
    {
        let now = self.t0.advanced(by: .milliseconds(time))
        let result = recovery.onAckReceived(
            ranges: ranges,
            ackDelay: .zero,
            in: .applicationData,
            handshakeConfirmed: true,
            now: now
        )
        recovery.onAckEnd(packetsLost: result.congestionLoss, now: now)
        return result
    }

    func testLossesSpanningThreePTOsAreAPersistentCongestion() {
        for algorithm in [CoreCongestionControlAlgorithm.newReno, .cubic, .prague] {
            var recovery = self.recovery(algorithm, sending: [20, 100, 200, 300])
            // PTO = 10 + 4 · 5 + 25 ms; three of them are 165 ms, less than from 20 to 200 ms.
            XCTAssertLessThan(recovery.persistentCongestionDuration, .milliseconds(180))
            let result = self.acknowledge([4...4], at: 310, &recovery)
            XCTAssertEqual(result.lost.map(\.packetNumber), [1, 2, 3], "\(algorithm)")
            XCTAssertTrue(result.congestionLoss)
            XCTAssertEqual(recovery.congestionWindow, recovery.minimumWindow, "\(algorithm)")
            XCTAssertNil(recovery.congestionRecoveryStartTime, "\(algorithm): the next loss reduces again")
        }
    }

    func testAnAcknowledgedPacketInBetweenEndsThePeriod() {
        var recovery = self.recovery(sending: [20, 100, 200, 300])
        let result = self.acknowledge([4...4, 2...2], at: 310, &recovery)
        XCTAssertEqual(result.lost.map(\.packetNumber), [1, 3])
        // Half of 12000 grown by the first acknowledged packet.
        XCTAssertEqual(recovery.congestionWindow, 6600, "a congestion event, not persistent congestion")
    }

    func testLossesWithinThreePTOsAreNoPersistentCongestion() {
        var recovery = self.recovery(sending: [20, 60, 100, 300])
        let result = self.acknowledge([4...4], at: 310, &recovery)
        XCTAssertEqual(result.lost.map(\.packetNumber), [1, 2, 3])
        XCTAssertEqual(recovery.congestionWindow, 6600)
    }

    func testPacketsSentBeforeTheFirstRTTSampleDontCount() {
        var recovery = CoreRecovery(congestionControl: .newReno)
        recovery.onPacketSent(Self.packet(0, at: self.t0), in: .applicationData)
        recovery.onPacketSent(Self.packet(1, at: self.t0.advanced(by: .milliseconds(1))), in: .applicationData)
        recovery.onPacketSent(Self.packet(2, at: self.t0.advanced(by: .milliseconds(250))), in: .applicationData)
        // The first sample, at 300 ms, comes after all of them: 250 ms of losses don't count.
        recovery.onPacketSent(Self.packet(3, at: self.t0.advanced(by: .milliseconds(290))), in: .applicationData)
        let now = self.t0.advanced(by: .milliseconds(300))
        let result = recovery.onAckReceived(
            ranges: [3...3],
            ackDelay: .zero,
            in: .applicationData,
            handshakeConfirmed: true,
            now: now
        )
        XCTAssertEqual(result.lost.map(\.packetNumber), [0, 1, 2])
        XCTAssertEqual(recovery.congestionWindow, 6000)
    }

    func testLostPMTUDProbesAreNoCongestionSignal() {
        var recovery = self.recovery(sending: [20, 100, 200, 300], probes: true)
        let window = recovery.congestionWindow
        let result = self.acknowledge([4...4], at: 310, &recovery)
        XCTAssertEqual(result.lost.map(\.packetNumber), [1, 2, 3])
        XCTAssertFalse(result.congestionLoss)
        XCTAssertNil(recovery.congestionRecoveryStartTime)
        // No reduction. Nor growth: four packets in 300 ms don't use the window (RFC 9002
        // Section 7.8).
        XCTAssertEqual(recovery.congestionWindow, window)
    }

    func testThePeriodDoesntStartAtALostProbe() {
        var period = CorePersistentCongestionPeriod(duration: .milliseconds(100), firstRTTSampleTime: self.t0)
        period.add(Self.packet(1, at: self.t0, probe: true), lost: true)
        period.add(Self.packet(2, at: self.t0.advanced(by: .milliseconds(50))), lost: true)
        period.add(Self.packet(3, at: self.t0.advanced(by: .milliseconds(120))), lost: false)
        period.add(Self.packet(4, at: self.t0.advanced(by: .milliseconds(140))), lost: true)
        XCTAssertFalse(period.isEstablished, "90 ms from the first lost packet that isn't a probe")
        period.add(Self.packet(5, at: self.t0.advanced(by: .milliseconds(150))), lost: true)
        XCTAssertTrue(period.isEstablished, "packets in flight in between don't end the period")
    }
}

#endif
