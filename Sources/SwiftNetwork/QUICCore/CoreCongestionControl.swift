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

@_spi(Essentials) @_spi(ProtocolProvider) import QUICStateMachine

#if !NETWORK_NO_SWIFT_QUIC

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#endif

/// The congestion controller of a connection.
@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public enum CoreCongestionControlAlgorithm: Equatable, Sendable {
    /// NewReno (RFC 9002 Section 7).
    case newReno
    /// CUBIC (RFC 9438), the default.
    case cubic
    /// Prague, the scalable congestion control of L4S (RFC 9331): DCTCP's reaction to CE marks,
    /// CUBIC's after a loss. Its packets go out ECT(1) and paced.
    case prague
}

/// What every congestion controller works on: the window, the slow start threshold and the
/// recovery period (RFC 9002 Section 7), and the bytes the ACK frame being processed newly
/// acknowledged.
@available(Network 0.1.0, *)
struct CoreCongestionState {
    var maxDatagramSize: Int
    var congestionWindow: Int
    var slowStartThreshold = Int.max
    /// When the current recovery period started; `nil` outside one.
    var recoveryStartTime: NetworkClock.Instant?
    /// What the ACK frame being processed newly acknowledged of the packets in flight that went
    /// out after the recovery period started. Only these grow the window (RFC 9002 Section 7.3.2).
    var bytesAcknowledged = 0
    /// The bytes in flight, which the loss detection keeps.
    var bytesInFlight = 0

    init(maxDatagramSize: Int) {
        self.maxDatagramSize = maxDatagramSize
        self.congestionWindow = Self.initialWindow(maxDatagramSize: maxDatagramSize)
    }

    /// RFC 9002 Section 7.2.
    static func initialWindow(maxDatagramSize: Int) -> Int {
        min(10 &* maxDatagramSize, max(14720, 2 &* maxDatagramSize))
    }

    var minimumWindow: Int { 2 &* self.maxDatagramSize }

    var inSlowStart: Bool { self.congestionWindow < self.slowStartThreshold }

    /// Whether a packet sent at `sentTime` went out before the current recovery period started.
    func inRecovery(sentTime: NetworkClock.Instant) -> Bool {
        guard let start = self.recoveryStartTime else { return false }
        return sentTime <= start
    }
}

/// The ECN feedback of an ACK frame, once the path is validated as ECN-capable (RFC 9000 Section
/// 13.4.2).
@available(Network 0.1.0, *)
struct CoreECNFeedback {
    /// The packets the peer newly reported CE.
    var newlyCE: UInt64
    /// The packets that went out ECN-capable that the frame newly acknowledged.
    var newlyAcknowledged: UInt64
    var largestAcknowledged: UInt64
    /// The largest packet number sent so far, which ends the round that starts now.
    var largestSent: UInt64
    /// When the largest newly acknowledged packet went out (RFC 9002 Section B.7).
    var largestAcknowledgedSentTime: NetworkClock.Instant
}

/// A congestion controller. Every method gets the shared state; conformers keep what is their
/// own. They are value types, dispatched statically through ``CoreCongestionController``.
@available(Network 0.1.0, *)
protocol CoreCongestionControllerProtocol {
    /// The pacer sends a burst of its rate divided by 2 to the power of this, every interval.
    static var burstShift: UInt64 { get }

    init(state: inout CoreCongestionState)

    /// Grows the window by the bytes the ACK frame acknowledged, unless it declared packets
    /// lost.
    mutating func onAckEnd(
        state: inout CoreCongestionState,
        packetsLost: Bool,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    )

    /// Packets were lost, the last one sent at `sentTime`. Returns whether a recovery period
    /// started.
    mutating func onCongestionEvent(
        state: inout CoreCongestionState,
        sentTime: NetworkClock.Instant,
        now: NetworkClock.Instant
    ) -> Bool

    mutating func onECNFeedback(
        state: inout CoreCongestionState,
        _ feedback: CoreECNFeedback,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    )

    /// Collapses the window to the minimum (RFC 9002 Section 7.6.2).
    mutating func onPersistentCongestion(state: inout CoreCongestionState)
}

/// One of the congestion controllers, as an enum of value types so that every call is a switch
/// and a direct call, never a witness table or an allocation.
@available(Network 0.1.0, *)
enum CoreCongestionController {
    case newReno(CoreNewReno)
    case cubic(CoreCubic)
    case prague(CorePrague)

    init(_ algorithm: CoreCongestionControlAlgorithm, state: inout CoreCongestionState) {
        switch algorithm {
        case .newReno: self = .newReno(CoreNewReno(state: &state))
        case .cubic: self = .cubic(CoreCubic(state: &state))
        case .prague: self = .prague(CorePrague(state: &state))
        }
    }

    var algorithm: CoreCongestionControlAlgorithm {
        switch self {
        case .newReno: return .newReno
        case .cubic: return .cubic
        case .prague: return .prague
        }
    }

    var burstShift: UInt64 {
        switch self {
        case .newReno: return CoreNewReno.burstShift
        case .cubic: return CoreCubic.burstShift
        case .prague: return CorePrague.burstShift
        }
    }

    mutating func onAckEnd(
        state: inout CoreCongestionState,
        packetsLost: Bool,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        switch self {
        case .newReno(var controller):
            controller.onAckEnd(state: &state, packetsLost: packetsLost, smoothedRTT: smoothedRTT, now: now)
            self = .newReno(controller)
        case .cubic(var controller):
            controller.onAckEnd(state: &state, packetsLost: packetsLost, smoothedRTT: smoothedRTT, now: now)
            self = .cubic(controller)
        case .prague(var controller):
            controller.onAckEnd(state: &state, packetsLost: packetsLost, smoothedRTT: smoothedRTT, now: now)
            self = .prague(controller)
        }
    }

    @discardableResult
    mutating func onCongestionEvent(
        state: inout CoreCongestionState,
        sentTime: NetworkClock.Instant,
        now: NetworkClock.Instant
    ) -> Bool {
        switch self {
        case .newReno(var controller):
            defer { self = .newReno(controller) }
            return controller.onCongestionEvent(state: &state, sentTime: sentTime, now: now)
        case .cubic(var controller):
            defer { self = .cubic(controller) }
            return controller.onCongestionEvent(state: &state, sentTime: sentTime, now: now)
        case .prague(var controller):
            defer { self = .prague(controller) }
            return controller.onCongestionEvent(state: &state, sentTime: sentTime, now: now)
        }
    }

    mutating func onECNFeedback(
        state: inout CoreCongestionState,
        _ feedback: CoreECNFeedback,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        switch self {
        case .newReno(var controller):
            controller.onECNFeedback(state: &state, feedback, smoothedRTT: smoothedRTT, now: now)
            self = .newReno(controller)
        case .cubic(var controller):
            controller.onECNFeedback(state: &state, feedback, smoothedRTT: smoothedRTT, now: now)
            self = .cubic(controller)
        case .prague(var controller):
            controller.onECNFeedback(state: &state, feedback, smoothedRTT: smoothedRTT, now: now)
            self = .prague(controller)
        }
    }

    mutating func onPersistentCongestion(state: inout CoreCongestionState) {
        switch self {
        case .newReno(var controller):
            controller.onPersistentCongestion(state: &state)
            self = .newReno(controller)
        case .cubic(var controller):
            controller.onPersistentCongestion(state: &state)
            self = .cubic(controller)
        case .prague(var controller):
            controller.onPersistentCongestion(state: &state)
            self = .prague(controller)
        }
    }
}

// MARK: - NewReno

/// NewReno (RFC 9002 Section 7 and Appendix B).
@available(Network 0.1.0, *)
struct CoreNewReno: CoreCongestionControllerProtocol {
    static let burstShift: UInt64 = 10

    var pipeAck = CorePipeAck()

    init(state: inout CoreCongestionState) {
        state.congestionWindow = CoreCongestionState.initialWindow(maxDatagramSize: state.maxDatagramSize)
    }

    mutating func onAckEnd(
        state: inout CoreCongestionState,
        packetsLost: Bool,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        // An ACK frame that declared packets lost doesn't grow the window, as with the other
        // controllers; RFC 9002 Section B.5 would grow it before the losses halve it.
        let acknowledged = state.bytesAcknowledged
        guard !packetsLost, acknowledged > 0 else { return }
        guard
            self.pipeAck.revalidate(
                bytesAcknowledged: acknowledged,
                congestionWindow: state.congestionWindow,
                inSlowStart: state.inSlowStart,
                smoothedRTT: smoothedRTT,
                now: now
            )
        else {
            // The sender doesn't use the window: it mustn't grow (RFC 9002 Section 7.8).
            return
        }
        if state.inSlowStart {
            state.congestionWindow &+= acknowledged
        } else {
            state.congestionWindow &+= state.maxDatagramSize &* acknowledged / state.congestionWindow
        }
    }

    /// Halves the window, unless the packet went out during the current recovery period (RFC
    /// 9002 Section B.6).
    mutating func onCongestionEvent(
        state: inout CoreCongestionState,
        sentTime: NetworkClock.Instant,
        now: NetworkClock.Instant
    ) -> Bool {
        guard !state.inRecovery(sentTime: sentTime) else { return false }
        state.recoveryStartTime = now
        state.slowStartThreshold = max(state.congestionWindow / 2, state.minimumWindow)
        state.congestionWindow = state.slowStartThreshold
        // The samples were of the larger window.
        self.pipeAck.reset()
        return true
    }

    /// A CE mark is a congestion event for the largest acknowledged packet (RFC 9002 Section B.7).
    mutating func onECNFeedback(
        state: inout CoreCongestionState,
        _ feedback: CoreECNFeedback,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        guard feedback.newlyCE > 0 else { return }
        _ = self.onCongestionEvent(state: &state, sentTime: feedback.largestAcknowledgedSentTime, now: now)
    }

    mutating func onPersistentCongestion(state: inout CoreCongestionState) {
        state.congestionWindow = state.minimumWindow
    }
}

// MARK: - Congestion window validation

/// Whether the window is used, after RFC 7661's pipeACK: a window the sender doesn't fill
/// mustn't grow, and a loss reduces what was in flight rather than the window. RFC 9438 Section
/// 4.6 requires one or the other of a CUBIC that reduces the window, not the flight size.
@available(Network 0.1.0, *)
struct CorePipeAck {
    static let sampleCount = 3

    /// The bytes acknowledged per RTT, in the last three RTTs.
    var samples: InlineArray<3, Int> = .init(repeating: 0)
    var index = 0
    /// The largest sample; zero before the first one, which validates any window.
    var value = 0
    /// When the current sample ends.
    var sampleEnd: NetworkClock.Instant?
    var acknowledged = 0

    mutating func reset() {
        self.samples = .init(repeating: 0)
        self.index = 0
        self.value = 0
    }

    func isValidated(congestionWindow: Int, inSlowStart: Bool) -> Bool {
        guard self.value > 0 else { return true }
        // In slow start the window doubles each RTT and pipeACK lags behind: a quarter will do.
        return self.value >= (inSlowStart ? congestionWindow >> 2 : congestionWindow >> 1)
    }

    /// What a loss reduces: the window if the sender used it, what was in flight otherwise.
    func lossFlightSize(congestionWindow: Int, inSlowStart: Bool, bytesInFlight: Int) -> Int {
        self.isValidated(congestionWindow: congestionWindow, inSlowStart: inSlowStart)
            ? congestionWindow : max(self.value, bytesInFlight)
    }

    private mutating func addSample(_ sample: Int) {
        self.samples[self.index] = sample
        self.index = (self.index &+ 1) % Self.sampleCount
    }

    /// Counts the bytes an ACK frame acknowledged. Returns whether the window is validated.
    mutating func revalidate(
        bytesAcknowledged: Int,
        congestionWindow: Int,
        inSlowStart: Bool,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) -> Bool {
        if self.sampleEnd == nil {
            self.sampleEnd = now.advanced(by: smoothedRTT)
            self.acknowledged = 0
        }
        self.acknowledged &+= bytesAcknowledged
        if let sampleEnd = self.sampleEnd, now > sampleEnd {
            let period = sampleEnd.duration(to: now)
            if period > smoothedRTT {
                // An RTT or more without acknowledgements counts as nothing acknowledged.
                self.addSample(0)
                if period > smoothedRTT * 2 {
                    self.addSample(0)
                }
            }
            self.addSample(self.acknowledged)
            self.value = self.acknowledged
            for index in 0..<Self.sampleCount where self.samples[index] > self.value {
                self.value = self.samples[index]
            }
            self.sampleEnd = now.advanced(by: smoothedRTT)
            self.acknowledged = 0
        }
        return self.isValidated(congestionWindow: congestionWindow, inSlowStart: inSlowStart)
    }
}

// MARK: - CUBIC

/// CUBIC (RFC 9438), as `Cubic` of the classes: β 0.7, C 0.4, fast convergence, the
/// Reno-friendly region, and RFC 7661 congestion window validation.
@available(Network 0.1.0, *)
struct CoreCubic: CoreCongestionControllerProtocol {
    static let burstShift: UInt64 = 10
    static let beta = 0.7
    static let c = 0.4

    /// The time the window takes to grow back to `maxWindow`, in seconds.
    var k: Double = 0
    var congestionEvents = 0
    /// Bytes acknowledged towards the next CUBIC increase.
    var cubicAcknowledged = 0
    /// Bytes acknowledged towards the Reno-friendly window.
    var renoAcknowledged = 0
    /// W_max before the last reduction, for fast convergence.
    var lastMaxWindow = 0
    /// W_max: the window before the last reduction.
    var maxWindow = 0
    var originPoint = 0
    /// When the current congestion avoidance period started; `nil` until it does.
    var epochStart: NetworkClock.Instant?
    /// W_est, the window Reno would have.
    var renoWindow = 0
    var pipeAck = CorePipeAck()
    /// The largest packet number sent when the window last shrank for CE marks; marks of packets
    /// up to it belong to that reduction.
    var ceRoundEnd: UInt64?

    init(state: inout CoreCongestionState) {
        state.congestionWindow = CoreCongestionState.initialWindow(maxDatagramSize: state.maxDatagramSize)
        state.slowStartThreshold = .max
        self.maxWindow = state.congestionWindow
    }

    mutating func onAckEnd(
        state: inout CoreCongestionState,
        packetsLost: Bool,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        guard !packetsLost, state.bytesAcknowledged > 0 else { return }
        guard
            self.pipeAck.revalidate(
                bytesAcknowledged: state.bytesAcknowledged,
                congestionWindow: state.congestionWindow,
                inSlowStart: state.inSlowStart,
                smoothedRTT: smoothedRTT,
                now: now
            )
        else {
            // The sender doesn't use the window: it mustn't grow (RFC 9002 Section 7.8).
            return
        }
        if state.inSlowStart {
            // At most ten datagrams per ACK frame.
            state.congestionWindow &+= min(state.bytesAcknowledged, 10 &* state.maxDatagramSize)
        } else {
            self.congestionAvoidance(state: &state, smoothedRTT: smoothedRTT, now: now)
        }
        state.congestionWindow = max(state.congestionWindow, state.minimumWindow)
    }

    /// RFC 9438 Section 4.2: grows towards W_cubic(t + RTT), and at least as fast as Reno would.
    mutating func congestionAvoidance(
        state: inout CoreCongestionState,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        let acknowledged = state.bytesAcknowledged
        let mss = state.maxDatagramSize
        self.cubicAcknowledged &+= acknowledged
        let target = self.target(state: state, smoothedRTT: smoothedRTT, now: now)

        // W_est += α_cubic · acknowledged / cwnd (RFC 9438 Section 4.3); α is 1 above W_max.
        self.renoAcknowledged &+= acknowledged
        let alpha = self.renoWindow < self.maxWindow ? 3 * (1 - Self.beta) / (1 + Self.beta) : 1
        self.renoWindow &+= Int(alpha * Double(acknowledged) * Double(mss) / Double(max(1, self.renoWindow)))

        if state.congestionWindow < target {
            // The increase over an RTT is target - cwnd; this ACK gets its share, at most an
            // initial window.
            let increase =
                Double(target &- state.congestionWindow) * Double(self.cubicAcknowledged)
                / Double(state.congestionWindow)
            state.congestionWindow &+= min(Int(increase), CoreCongestionState.initialWindow(maxDatagramSize: mss))
            self.cubicAcknowledged = 0
        }
        if state.congestionWindow < self.renoWindow {
            // The Reno-friendly region.
            state.congestionWindow = self.renoWindow
            self.cubicAcknowledged = max(0, self.cubicAcknowledged &- self.renoAcknowledged)
            self.renoAcknowledged = 0
        }
        if self.congestionEvents == 0 {
            // Before the first congestion event, W_max follows the window.
            self.maxWindow = state.congestionWindow
        }
    }

    /// W_cubic(t + RTT) = C · (t + RTT - K)³ + W_max (RFC 9438 Section 4.2), in bytes.
    private mutating func target(
        state: CoreCongestionState,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    )
        -> Int
    {
        let epochStart: NetworkClock.Instant
        if let start = self.epochStart {
            epochStart = start
        } else {
            // Congestion avoidance without a loss first: t counts from now.
            epochStart = now
            self.epochStart = now
            if state.congestionWindow < self.maxWindow {
                self.originPoint = self.maxWindow
                self.k = Self.k(maxWindow: self.maxWindow, window: state.congestionWindow, mss: state.maxDatagramSize)
            } else {
                self.originPoint = state.congestionWindow
                self.k = 0
            }
            self.renoWindow = state.congestionWindow
            self.renoAcknowledged = 0
        }
        let elapsed = epochStart.duration(to: now) + smoothedRTT
        var offset = Self.seconds(elapsed) - self.k
        offset = offset * offset * offset * Self.c * Double(state.maxDatagramSize)
        let window = Double(self.originPoint) + offset
        return window > 0 ? Int(min(window, Double(Int.max / 2))) : 0
    }

    /// K = ∛(W_max · (1 - β) / C), from the window after the reduction (RFC 9438 Section 4.2).
    static func k(maxWindow: Int, window: Int, mss: Int) -> Double {
        guard maxWindow > window else { return 0 }
        return Self.cubeRoot(Double(maxWindow &- window) / Self.c / Double(mss))
    }

    static func seconds(_ duration: NetworkDuration) -> Double {
        Double(duration.nanoseconds) / 1_000_000_000
    }

    static func cubeRoot(_ value: Double) -> Double {
        #if canImport(Darwin) || canImport(Glibc) || canImport(Musl) || canImport(Android)
        return cbrt(value)
        #else
        guard value > 0 else { return 0 }
        var guess = value > 1 ? value / 2 : value
        for _ in 0..<100 {
            let next = (2 * guess + value / (guess * guess)) / 3
            if abs(next - guess) < 1e-12 { return next }
            guess = next
        }
        return guess
        #endif
    }

    mutating func onCongestionEvent(
        state: inout CoreCongestionState,
        sentTime: NetworkClock.Instant,
        now: NetworkClock.Instant
    ) -> Bool {
        guard !state.inRecovery(sentTime: sentTime) else { return false }
        self.enterRecovery(state: &state, now: now)
        return true
    }

    /// RFC 9438 Section 4.6: β times the window, or what was in flight if the window wasn't used;
    /// fast convergence (Section 4.7) lowers W_max when it shrank.
    mutating func enterRecovery(state: inout CoreCongestionState, now: NetworkClock.Instant) {
        let mss = state.maxDatagramSize
        state.recoveryStartTime = now
        self.lastMaxWindow = self.maxWindow
        self.maxWindow = state.congestionWindow
        let flightSize = self.pipeAck.lossFlightSize(
            congestionWindow: state.congestionWindow,
            inSlowStart: state.inSlowStart,
            bytesInFlight: state.bytesInFlight
        )
        state.congestionWindow = max(Int(Double(flightSize) * Self.beta), state.minimumWindow)
        state.slowStartThreshold = state.congestionWindow
        if self.maxWindow < self.lastMaxWindow {
            self.maxWindow = max(Int(Double(self.maxWindow) * (1 + Self.beta) / 2), state.minimumWindow)
        }
        self.k = Self.k(maxWindow: self.maxWindow, window: state.congestionWindow, mss: mss)
        self.epochStart = now
        self.originPoint = self.maxWindow
        self.renoWindow = state.congestionWindow
        self.renoAcknowledged = 0
        self.congestionEvents &+= 1
        self.pipeAck.reset()
    }

    /// RFC 9438 Section 4.6 treats a CE mark like a loss: at most once per round, and not for a
    /// packet sent during the recovery period.
    mutating func onECNFeedback(
        state: inout CoreCongestionState,
        _ feedback: CoreECNFeedback,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        guard feedback.newlyCE > 0 else { return }
        // An ACK frame with new marks doesn't grow the window.
        state.bytesAcknowledged = 0
        if let roundEnd = self.ceRoundEnd, feedback.largestAcknowledged <= roundEnd {
            return
        }
        if self.onCongestionEvent(state: &state, sentTime: feedback.largestAcknowledgedSentTime, now: now) {
            self.ceRoundEnd = feedback.largestSent
        }
    }

    /// RFC 9002 Section 7.6.2; the threshold stays where the last reduction put it, at least β
    /// times the window.
    mutating func onPersistentCongestion(state: inout CoreCongestionState) {
        state.slowStartThreshold = max(Int(Double(state.congestionWindow) * Self.beta), state.minimumWindow)
        state.congestionWindow = state.minimumWindow
    }
}

// MARK: - Prague

/// Prague (draft-briscoe-iccrg-prague-congestion-control), as `Prague` of the classes: the
/// window shrinks by α/2 once per RTT with CE marks, α being the moving average of the fraction
/// of marked packets (DCTCP, RFC 8257); losses get CUBIC's reaction.
@available(Network 0.1.0, *)
struct CorePrague: CoreCongestionControllerProtocol {
    /// A burst of about 250 µs: L4S queues are short.
    static let burstShift: UInt64 = 12
    /// α is a fraction in units of 2^-20.
    static let alphaShift = 20
    /// The gain g of the moving average, 1/16.
    static let gShift = 4
    static let maxAlpha = 1 << alphaShift
    /// The reference RTT of the additive increase after a CE reduction (RTT independence), 20 ms.
    static let referenceRTTMicroseconds = 20_000

    /// The window growth and the reaction to losses.
    var cubic: CoreCubic
    /// α divided by g. It starts at one, as DCTCP's: the first marks halve the window.
    var scaledAlpha = CorePrague.maxAlpha << CorePrague.gShift
    /// The packets acknowledged and marked in the current round, for α.
    var roundAcknowledged: UInt64 = 0
    var roundMarked: UInt64 = 0
    /// The largest packet number sent when the round for α started.
    var alphaRoundEnd: UInt64?
    /// The same, for the last CE reduction.
    var ceRoundEnd: UInt64?
    /// Whether the last reduction was for CE marks, after which the window grows by Reno's
    /// additive increase, scaled for RTT independence.
    var reducedForCE = false
    /// The additive increase per RTT after a CE reduction, in datagrams, in units of 2^-20.
    var additiveIncrease = 1 << CorePrague.alphaShift

    var alpha: Int { self.scaledAlpha >> Self.gShift }

    init(state: inout CoreCongestionState) {
        self.cubic = CoreCubic(state: &state)
    }

    mutating func onAckEnd(
        state: inout CoreCongestionState,
        packetsLost: Bool,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        guard self.reducedForCE, !state.inSlowStart else {
            self.cubic.onAckEnd(state: &state, packetsLost: packetsLost, smoothedRTT: smoothedRTT, now: now)
            return
        }
        guard !packetsLost, state.bytesAcknowledged > 0 else { return }
        guard
            self.cubic.pipeAck.revalidate(
                bytesAcknowledged: state.bytesAcknowledged,
                congestionWindow: state.congestionWindow,
                inSlowStart: false,
                smoothedRTT: smoothedRTT,
                now: now
            )
        else {
            return
        }
        // cwnd += additiveIncrease · mss · acknowledged / cwnd, rounded.
        let increase =
            (state.bytesAcknowledged &* state.maxDatagramSize &* self.additiveIncrease &+ (state.congestionWindow >> 1))
            / state.congestionWindow
        state.congestionWindow &+= increase >> Self.alphaShift
        state.congestionWindow = max(state.congestionWindow, state.minimumWindow)
    }

    mutating func onCongestionEvent(
        state: inout CoreCongestionState,
        sentTime: NetworkClock.Instant,
        now: NetworkClock.Instant
    ) -> Bool {
        guard self.cubic.onCongestionEvent(state: &state, sentTime: sentTime, now: now) else { return false }
        self.reducedForCE = false
        return true
    }

    mutating func onECNFeedback(
        state: inout CoreCongestionState,
        _ feedback: CoreECNFeedback,
        smoothedRTT: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        self.updateAlpha(feedback)
        guard feedback.newlyCE > 0 else { return }
        // Only the unmarked bytes grow the window.
        state.bytesAcknowledged = max(
            0,
            state.bytesAcknowledged &- Int(truncatingIfNeeded: feedback.newlyCE) &* state.maxDatagramSize
        )
        self.updateAdditiveIncrease(smoothedRTT: smoothedRTT)
        if let roundEnd = self.ceRoundEnd, feedback.largestAcknowledged <= roundEnd {
            // One reduction per RTT (CWR).
            return
        }
        guard !state.inRecovery(sentTime: feedback.largestAcknowledgedSentTime) else { return }
        // cwnd · (1 - α/2).
        let reduction = (state.congestionWindow &* self.alpha) >> (Self.alphaShift &+ 1)
        state.congestionWindow = max(state.congestionWindow &- reduction, state.minimumWindow)
        state.slowStartThreshold = state.congestionWindow
        self.reducedForCE = true
        self.ceRoundEnd = feedback.largestSent
    }

    /// α = (1 - g) · α + g · F once per round, F being the fraction of the packets acknowledged
    /// in the round that were marked (RFC 8257 Section 3.3).
    private mutating func updateAlpha(_ feedback: CoreECNFeedback) {
        self.roundAcknowledged &+= feedback.newlyAcknowledged
        self.roundMarked &+= feedback.newlyCE
        if let roundEnd = self.alphaRoundEnd, feedback.largestAcknowledged <= roundEnd {
            return
        }
        if self.roundAcknowledged > 0 {
            let marked = min(self.roundMarked, self.roundAcknowledged)
            let fraction = Int(truncatingIfNeeded: (marked << UInt64(Self.alphaShift)) / self.roundAcknowledged)
            let scaled = self.scaledAlpha &- (self.scaledAlpha >> Self.gShift) &+ fraction
            self.scaledAlpha = min(Self.maxAlpha << Self.gShift, scaled)
        }
        self.roundAcknowledged = 0
        self.roundMarked = 0
        self.alphaRoundEnd = feedback.largestSent
    }

    /// RTT independence by rate equivalence: below the reference RTT, the increase per RTT is
    /// (RTT / reference RTT)², which gives flows of different RTTs the same rate.
    private mutating func updateAdditiveIncrease(smoothedRTT: NetworkDuration) {
        let rtt = Int(smoothedRTT.nanoseconds / 1000)
        let reference = Self.referenceRTTMicroseconds
        guard rtt < reference else {
            self.additiveIncrease = 1 << Self.alphaShift
            return
        }
        let divisor = reference &* reference
        self.additiveIncrease = (((rtt &* rtt) << Self.alphaShift) &+ (divisor >> 1)) / divisor
    }

    mutating func onPersistentCongestion(state: inout CoreCongestionState) {
        self.cubic.onPersistentCongestion(state: &state)
        self.reducedForCE = false
    }
}

#endif
