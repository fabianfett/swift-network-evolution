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

#if canImport(BasicContainers)
internal import DequeModule
#endif

/// A frame recorded in a sent packet, so it can be acted on when the packet is acknowledged or
/// lost.
@available(Network 0.1.0, *)
enum CoreSentFrame {
    case ack(largestAcknowledged: UInt64)
    case crypto(offset: UInt64, length: Int)
    case stream(id: UInt64, offset: UInt64, length: Int, fin: Bool)
    case resetStream(id: UInt64)
    case stopSending(id: UInt64)
    case maxData
    case maxStreamData(id: UInt64)
    case maxStreamsBidirectional
    case maxStreamsUnidirectional
    case dataBlocked
    case streamDataBlocked(id: UInt64)
    case newConnectionID(sequenceNumber: UInt64)
    case retireConnectionID(sequenceNumber: UInt64)
    case pathResponse
    case handshakeDone
    case ping
    case pathChallenge
    /// The PING of a keepalive.
    case keepAlive
    case datagram
}

@available(Network 0.1.0, *)
struct CoreSentPacket {
    var packetNumber: UInt64
    var timeSent: NetworkClock.Instant
    var size: Int
    var isAckEliciting: Bool
    var isInFlight: Bool
    var frames: [CoreSentFrame]
}

/// Loss detection (RFC 9002 Section 6) and NewReno congestion control (RFC 9002 Section 7).
@available(Network 0.1.0, *)
struct CoreRecovery {
    static let packetThreshold: UInt64 = 3
    static let granularity = NetworkDuration.milliseconds(1)
    static let initialRTT = NetworkDuration.milliseconds(333)
    static let persistentCongestionThreshold: Int64 = 3

    struct Space {
        /// Sent packets that are not acknowledged or declared lost, ordered by packet number.
        var sent = Deque<CoreSentPacket>()
        var largestAcknowledged: UInt64?
        var lossTime: NetworkClock.Instant?
        var timeOfLastAckElicitingPacket: NetworkClock.Instant?
        var ackElicitingInFlight = 0
    }

    struct AckResult {
        var acknowledged: [CoreSentPacket] = []
        var lost: [CoreSentPacket] = []
        /// Whether the largest acknowledged packet was newly acknowledged and ack-eliciting, which
        /// makes it an RTT sample.
        var rttSampled = false
    }

    enum Timeout {
        case lost([CoreSentPacket], PacketNumberSpace)
        case probe(PacketNumberSpace)
    }

    var spaces = [Space(), Space(), Space()]

    var latestRTT = NetworkDuration.zero
    var smoothedRTT = CoreRecovery.initialRTT
    var rttVariance = CoreRecovery.initialRTT / 2
    var minRTT = NetworkDuration.zero
    var hasRTTSample = false
    /// The peer's maximum ACK delay, from its transport parameters.
    var maxAckDelay = NetworkDuration.milliseconds(25)

    var ptoCount = 0

    var maxDatagramSize: Int
    var congestionWindow: Int
    var bytesInFlight = 0
    var slowStartThreshold = Int.max
    var congestionRecoveryStartTime: NetworkClock.Instant?
    /// When datagrams leave, if the connection paces; `nil` otherwise.
    var pacer: CorePacer?

    init(maxDatagramSize: Int = 1200, pacingEnabled: Bool = false) {
        self.maxDatagramSize = maxDatagramSize
        self.congestionWindow = Self.initialWindow(maxDatagramSize: maxDatagramSize)
        if pacingEnabled {
            var pacer = CorePacer()
            pacer.reset(congestionWindow: self.congestionWindow, maxDatagramSize: maxDatagramSize)
            self.pacer = pacer
        }
    }

    static func initialWindow(maxDatagramSize: Int) -> Int {
        min(10 * maxDatagramSize, max(14720, 2 * maxDatagramSize))
    }

    var minimumWindow: Int { 2 * self.maxDatagramSize }

    var availableCongestionWindow: Int {
        max(0, self.congestionWindow &- self.bytesInFlight)
    }

    var hasAckElicitingInFlight: Bool {
        self.spaces.contains { $0.ackElicitingInFlight > 0 }
    }

    // MARK: Sending

    mutating func onPacketSent(_ packet: CoreSentPacket, in space: PacketNumberSpace) {
        let index = Int(space.rawValue)
        if packet.isInFlight {
            if packet.isAckEliciting {
                self.spaces[index].timeOfLastAckElicitingPacket = packet.timeSent
                self.spaces[index].ackElicitingInFlight &+= 1
            }
            self.bytesInFlight &+= packet.size
        }
        if packet.isInFlight || packet.isAckEliciting || !packet.frames.isEmpty {
            self.spaces[index].sent.append(packet)
        }
    }

    // MARK: Acknowledgements

    /// Processes an ACK frame. `ranges` are the acknowledged packet number ranges, descending.
    mutating func onAckReceived(
        ranges: [ClosedRange<UInt64>],
        ackDelay: NetworkDuration,
        in space: PacketNumberSpace,
        handshakeConfirmed: Bool,
        now: NetworkClock.Instant
    ) -> AckResult {
        var result = AckResult()
        guard let largest = ranges.first?.upperBound else { return result }
        let index = Int(space.rawValue)

        if let previous = self.spaces[index].largestAcknowledged {
            self.spaces[index].largestAcknowledged = max(previous, largest)
        } else {
            self.spaces[index].largestAcknowledged = largest
        }

        // Remove acknowledged packets. They lie between the smallest and the largest acknowledged
        // packet number, so only that part of the queue changes.
        let lower = Self.firstIndex(in: self.spaces[index].sent, atLeast: ranges[ranges.count &- 1].lowerBound)
        let upper = Self.firstIndex(in: self.spaces[index].sent, above: largest)
        var kept: [CoreSentPacket] = []
        var largestNewlyAcked: CoreSentPacket?
        var ackedAckEliciting = false
        for position in lower..<upper {
            let packet = self.spaces[index].sent[position]
            if Self.contains(ranges, packet.packetNumber) {
                if packet.isInFlight {
                    self.bytesInFlight &-= packet.size
                    if packet.isAckEliciting {
                        self.spaces[index].ackElicitingInFlight &-= 1
                        ackedAckEliciting = true
                    }
                }
                // Ascending order: the last one is the largest.
                largestNewlyAcked = packet
                result.acknowledged.append(packet)
            } else {
                kept.append(packet)
            }
        }
        if lower < upper {
            self.spaces[index].sent.replaceSubrange(lower..<upper, with: kept)
        }

        guard let largestNewlyAcked else { return result }

        // RTT sample (RFC 9002 Section 5.1).
        if largestNewlyAcked.packetNumber == largest, ackedAckEliciting {
            self.updateRTT(
                sample: largestNewlyAcked.timeSent.duration(to: now),
                ackDelay: ackDelay,
                handshakeConfirmed: handshakeConfirmed
            )
            result.rttSampled = true
        }

        result.lost = self.detectLostPackets(in: space, now: now)

        // Congestion control.
        for packet in result.acknowledged where packet.isInFlight {
            self.onPacketAcknowledgedCongestionControl(packet)
        }
        if !result.lost.isEmpty {
            self.onPacketsLostCongestionControl(result.lost, now: now)
        }
        self.updatePacer()

        // Reset the PTO backoff, unless the client is unsure the server validated its address.
        self.ptoCount = 0
        return result
    }

    /// The position of the first packet numbered `packetNumber` or higher.
    private static func firstIndex(in sent: Deque<CoreSentPacket>, atLeast packetNumber: UInt64) -> Int {
        var low = 0
        var high = sent.count
        while low < high {
            let middle = low &+ (high &- low) / 2
            if sent[middle].packetNumber < packetNumber {
                low = middle &+ 1
            } else {
                high = middle
            }
        }
        return low
    }

    /// The position of the first packet numbered above `packetNumber`.
    private static func firstIndex(in sent: Deque<CoreSentPacket>, above packetNumber: UInt64) -> Int {
        packetNumber == .max ? sent.count : Self.firstIndex(in: sent, atLeast: packetNumber &+ 1)
    }

    private static func contains(_ ranges: [ClosedRange<UInt64>], _ packetNumber: UInt64) -> Bool {
        for range in ranges {
            if range.contains(packetNumber) { return true }
            if range.upperBound < packetNumber { return false }
        }
        return false
    }

    private mutating func updateRTT(sample: NetworkDuration, ackDelay: NetworkDuration, handshakeConfirmed: Bool) {
        self.latestRTT = sample
        if !self.hasRTTSample {
            self.hasRTTSample = true
            self.minRTT = sample
            self.smoothedRTT = sample
            self.rttVariance = sample / 2
            return
        }
        self.minRTT = min(self.minRTT, sample)
        var ackDelay = ackDelay
        if handshakeConfirmed {
            ackDelay = min(ackDelay, self.maxAckDelay)
        }
        var adjusted = sample
        if sample >= self.minRTT + ackDelay {
            adjusted = sample - ackDelay
        }
        let difference = self.smoothedRTT > adjusted ? self.smoothedRTT - adjusted : adjusted - self.smoothedRTT
        self.rttVariance = (self.rttVariance * 3) / 4 + difference / 4
        self.smoothedRTT = (self.smoothedRTT * 7) / 8 + adjusted / 8
    }

    // MARK: Loss detection

    private var lossDelay: NetworkDuration {
        let rtt = max(self.latestRTT, self.smoothedRTT)
        return max(rtt + rtt / 8, Self.granularity)
    }

    mutating func detectLostPackets(in space: PacketNumberSpace, now: NetworkClock.Instant) -> [CoreSentPacket] {
        let index = Int(space.rawValue)
        guard let largestAcknowledged = self.spaces[index].largestAcknowledged else { return [] }
        self.spaces[index].lossTime = nil
        let lossDelay = self.lossDelay
        var lost: [CoreSentPacket] = []
        // Only packets up to the largest acknowledged one can be lost; they are at the front.
        let end = Self.firstIndex(in: self.spaces[index].sent, above: largestAcknowledged)
        var kept: [CoreSentPacket] = []
        for position in 0..<end {
            let packet = self.spaces[index].sent[position]
            let lostByTime = packet.timeSent.advanced(by: lossDelay) <= now
            let lostByCount = largestAcknowledged >= packet.packetNumber &+ Self.packetThreshold
            if lostByTime || lostByCount {
                if packet.isInFlight {
                    self.bytesInFlight &-= packet.size
                    if packet.isAckEliciting {
                        self.spaces[index].ackElicitingInFlight &-= 1
                    }
                }
                lost.append(packet)
            } else {
                let lossTime = packet.timeSent.advanced(by: lossDelay)
                if let existing = self.spaces[index].lossTime {
                    self.spaces[index].lossTime = min(existing, lossTime)
                } else {
                    self.spaces[index].lossTime = lossTime
                }
                kept.append(packet)
            }
        }
        if end > 0 {
            self.spaces[index].sent.replaceSubrange(0..<end, with: kept)
        }
        return lost
    }

    /// The probe timeout period, without backoff.
    func probeTimeout(includingMaxAckDelay: Bool) -> NetworkDuration {
        var pto = self.smoothedRTT + max(self.rttVariance * 4, Self.granularity)
        if includingMaxAckDelay {
            pto = pto + self.maxAckDelay
        }
        return pto
    }

    /// When the loss detection timer fires, and for which space (RFC 9002 Section 6.2.2.1).
    func lossDetectionDeadline(
        handshakeConfirmed: Bool,
        hasHandshakeKeys: Bool,
        peerAwaitingAddressValidation: Bool
    ) -> (deadline: NetworkClock.Instant, space: PacketNumberSpace)? {
        // Time threshold loss detection first.
        var earliestLoss: (NetworkClock.Instant, PacketNumberSpace)?
        for space in PacketNumberSpace.allCases {
            if let lossTime = self.spaces[Int(space.rawValue)].lossTime {
                if earliestLoss == nil || lossTime < earliestLoss!.0 {
                    earliestLoss = (lossTime, space)
                }
            }
        }
        if let earliestLoss {
            return (earliestLoss.0, earliestLoss.1)
        }

        guard self.hasAckElicitingInFlight || peerAwaitingAddressValidation else {
            return nil
        }

        let backoff = 1 << min(self.ptoCount, 30)
        // Before anything is in flight, a client arms the timer for an anti-deadlock probe.
        if !self.hasAckElicitingInFlight {
            let space: PacketNumberSpace = hasHandshakeKeys ? .handshake : .initial
            let duration = self.probeTimeout(includingMaxAckDelay: false) * backoff
            let base = self.spaces[Int(space.rawValue)].timeOfLastAckElicitingPacket ?? .zero
            return (base.advanced(by: duration), space)
        }

        var earliest: (NetworkClock.Instant, PacketNumberSpace)?
        for space in PacketNumberSpace.allCases {
            let spaceState = self.spaces[Int(space.rawValue)]
            guard spaceState.ackElicitingInFlight > 0 else { continue }
            if space == .applicationData && !handshakeConfirmed {
                // Application data probes wait for the handshake.
                break
            }
            let duration = self.probeTimeout(includingMaxAckDelay: space == .applicationData) * backoff
            guard let lastSent = spaceState.timeOfLastAckElicitingPacket else { continue }
            let deadline = lastSent.advanced(by: duration)
            if earliest == nil || deadline < earliest!.0 {
                earliest = (deadline, space)
            }
        }
        return earliest
    }

    mutating func onLossDetectionTimeout(
        handshakeConfirmed: Bool,
        hasHandshakeKeys: Bool,
        peerAwaitingAddressValidation: Bool,
        now: NetworkClock.Instant
    ) -> Timeout? {
        guard
            let (_, space) = self.lossDetectionDeadline(
                handshakeConfirmed: handshakeConfirmed,
                hasHandshakeKeys: hasHandshakeKeys,
                peerAwaitingAddressValidation: peerAwaitingAddressValidation
            )
        else {
            return nil
        }
        if self.spaces[Int(space.rawValue)].lossTime != nil {
            let lost = self.detectLostPackets(in: space, now: now)
            if !lost.isEmpty {
                self.onPacketsLostCongestionControl(lost, now: now)
                self.updatePacer()
            }
            return .lost(lost, space)
        }
        self.ptoCount &+= 1
        return .probe(space)
    }

    /// Stops tracking `space`, once its keys are discarded (RFC 9002 Section 6.4).
    mutating func discard(_ space: PacketNumberSpace) {
        let index = Int(space.rawValue)
        for packet in self.spaces[index].sent where packet.isInFlight {
            self.bytesInFlight &-= packet.size
        }
        self.spaces[index] = Space()
        self.ptoCount = 0
    }

    // MARK: Congestion control

    /// Starts the congestion controller over, for a new path (RFC 9000 Section 9.4).
    mutating func resetCongestionControl() {
        self.congestionWindow = Self.initialWindow(maxDatagramSize: self.maxDatagramSize)
        self.slowStartThreshold = .max
        self.congestionRecoveryStartTime = nil
        self.pacer?.reset(congestionWindow: self.congestionWindow, maxDatagramSize: self.maxDatagramSize)
    }

    /// Paces at the rate the congestion window allows per RTT, once it changed.
    private mutating func updatePacer() {
        guard self.pacer != nil else { return }
        self.pacer!.update(
            congestionWindow: self.congestionWindow,
            inSlowStart: self.congestionWindow < self.slowStartThreshold,
            smoothedRTT: self.smoothedRTT
        )
    }

    private mutating func onPacketAcknowledgedCongestionControl(_ packet: CoreSentPacket) {
        if let recoveryStart = self.congestionRecoveryStartTime, packet.timeSent <= recoveryStart {
            return
        }
        if self.congestionWindow < self.slowStartThreshold {
            self.congestionWindow &+= packet.size
        } else {
            self.congestionWindow &+= self.maxDatagramSize * packet.size / self.congestionWindow
        }
    }

    private mutating func onPacketsLostCongestionControl(_ lost: [CoreSentPacket], now: NetworkClock.Instant) {
        guard let lastLost = lost.max(by: { $0.timeSent < $1.timeSent }), lastLost.isInFlight else { return }
        if let recoveryStart = self.congestionRecoveryStartTime, lastLost.timeSent <= recoveryStart {
            return
        }
        self.congestionRecoveryStartTime = now
        self.slowStartThreshold = max(self.congestionWindow / 2, self.minimumWindow)
        self.congestionWindow = self.slowStartThreshold
    }
}

/// Kernel pacing (RFC 9002 Section 7.7): spreads the congestion window over the RTT in bursts.
/// It never holds a datagram back; each one gets the time it should leave at, which the driver
/// hands to the kernel.
@available(Network 0.1.0, *)
struct CorePacer {
    /// The RTT the startup rate assumes.
    static let startupRTT = NetworkDuration.milliseconds(100)
    /// The rate divided by this is the burst size: about a millisecond of data.
    static let burstShift: UInt64 = 10

    /// Bytes per second.
    var rate: UInt64 = 0
    var burstSize = 0
    /// When the current burst leaves; `nil` before the first datagram.
    var burstStart: NetworkClock.Instant?
    var burstBytes = 0

    /// Starts over at the startup rate: the window per 100 ms, a datagram per burst.
    mutating func reset(congestionWindow: Int, maxDatagramSize: Int) {
        self.rate = UInt64(congestionWindow) &* 1_000_000 / UInt64(Self.startupRTT.microseconds)
        self.burstSize = maxDatagramSize
    }

    /// Paces the window per smoothed RTT, twice that in slow start, which RFC 9002 Section 7.7
    /// allows so that pacing doesn't slow the window's growth.
    mutating func update(congestionWindow: Int, inSlowStart: Bool, smoothedRTT: NetworkDuration) {
        let microseconds = smoothedRTT.microseconds > 0 ? smoothedRTT.microseconds : Self.startupRTT.microseconds
        let window = UInt64(max(0, congestionWindow)) &* (inSlowStart ? 2 : 1)
        self.rate = window &* 1_000_000 / UInt64(microseconds)
        self.burstSize = Int(truncatingIfNeeded: self.rate >> Self.burstShift)
    }

    /// When a datagram of `length` bytes leaves: with the current burst, or a burst interval
    /// after it once the burst is full, but never before `now`.
    mutating func departureTime(ofDatagram length: Int, now: NetworkClock.Instant) -> NetworkClock.Instant {
        guard let burstStart = self.burstStart else {
            self.burstStart = now
            self.burstBytes = length
            return now
        }
        guard self.burstBytes >= self.burstSize else {
            self.burstBytes &+= length
            return burstStart
        }
        let next = max(now, burstStart.advanced(by: self.interval(forBytes: self.burstBytes)))
        self.burstStart = next
        self.burstBytes = length
        return next
    }

    /// How long `bytes` take at the rate, at most `Constants.maxBurstIntervalKernelPacing`.
    func interval(forBytes bytes: Int) -> NetworkDuration {
        let maximum = Constants.maxBurstIntervalKernelPacing
        guard self.rate > 0 else { return maximum }
        let nanoseconds = UInt64(max(0, bytes)) &* 1_000_000_000 / self.rate
        guard nanoseconds < UInt64(maximum.nanoseconds) else { return maximum }
        return .nanoseconds(Int64(nanoseconds))
    }
}

#endif
