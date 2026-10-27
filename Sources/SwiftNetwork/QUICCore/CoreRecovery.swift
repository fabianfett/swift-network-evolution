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
    /// The PING of a PMTUD probe, padded to a datagram of `size` bytes.
    case pmtudProbe(size: Int)
}

@available(Network 0.1.0, *)
struct CoreSentPacket {
    var packetNumber: UInt64
    var timeSent: NetworkClock.Instant
    var size: Int
    var isAckEliciting: Bool
    var isInFlight: Bool
    /// The ECN codepoint of the packet's datagram.
    var ecn: IPProtocol.ECN = .nonECT
    /// Whether the packet is one of the ECN validation packets of its path (RFC 9000 Section
    /// 13.4.2).
    var isECNValidation = false
    var frames: [CoreSentFrame]

    var isPMTUDProbe: Bool {
        if case .pmtudProbe = self.frames.first { return true }
        return false
    }
}

/// Loss detection (RFC 9002 Section 6), persistent congestion (Section 7.6), and the congestion
/// controller (Section 7) that the ACK frames and losses drive.
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
        /// The packets that went out ECN-capable, and the largest ECN counts the peer reported
        /// (RFC 9000 Section 13.4.2.1).
        var ecnCapableSent: UInt64 = 0
        var ecnFeedback = CoreECNCounts()
    }

    struct AckResult {
        var acknowledged: [CoreSentPacket] = []
        var lost: [CoreSentPacket] = []
        /// Whether the largest acknowledged packet was newly acknowledged and ack-eliciting, which
        /// makes it an RTT sample.
        var rttSampled = false
        /// When the largest newly acknowledged packet was sent.
        var largestNewlyAcknowledgedTimeSent: NetworkClock.Instant?
        /// Whether packets in flight other than PMTUD probes were declared lost.
        var congestionLoss = false
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
    /// When the first RTT sample was taken. Persistent congestion counts only packets sent after
    /// it (RFC 9002 Section 7.6.2).
    var firstRTTSampleTime: NetworkClock.Instant?
    /// The peer's maximum ACK delay, from its transport parameters.
    var maxAckDelay = NetworkDuration.milliseconds(25)

    var ptoCount = 0

    /// The window, threshold and recovery period, which the controller works on.
    var congestion: CoreCongestionState
    var controller: CoreCongestionController
    /// When datagrams leave, if the connection paces; `nil` otherwise.
    var pacer: CorePacer?

    init(
        maxDatagramSize: Int = 1200,
        pacingEnabled: Bool = false,
        congestionControl: CoreCongestionControlAlgorithm = .cubic
    ) {
        self.congestion = CoreCongestionState(maxDatagramSize: maxDatagramSize)
        self.controller = CoreCongestionController(congestionControl, state: &self.congestion)
        if pacingEnabled {
            var pacer = CorePacer()
            pacer.reset(congestionWindow: self.congestion.congestionWindow, maxDatagramSize: maxDatagramSize)
            self.pacer = pacer
        }
    }

    static func initialWindow(maxDatagramSize: Int) -> Int {
        CoreCongestionState.initialWindow(maxDatagramSize: maxDatagramSize)
    }

    var maxDatagramSize: Int { self.congestion.maxDatagramSize }
    var congestionWindow: Int { self.congestion.congestionWindow }
    var slowStartThreshold: Int { self.congestion.slowStartThreshold }
    var congestionRecoveryStartTime: NetworkClock.Instant? { self.congestion.recoveryStartTime }
    var minimumWindow: Int { self.congestion.minimumWindow }

    var bytesInFlight: Int {
        get { self.congestion.bytesInFlight }
        set { self.congestion.bytesInFlight = newValue }
    }

    /// PMTUD changed the largest datagram of the path.
    mutating func maxDatagramSizeChanged(to size: Int) {
        self.congestion.maxDatagramSize = size
        self.congestion.congestionWindow = max(self.congestion.congestionWindow, self.congestion.minimumWindow)
    }

    var availableCongestionWindow: Int {
        max(0, self.congestion.congestionWindow &- self.congestion.bytesInFlight)
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
    ///
    /// Losses reduce the window right away; what the frame acknowledged grows it in
    /// ``onAckEnd(packetsLost:now:)``, after the frame's ECN counts were looked at.
    mutating func onAckReceived(
        ranges: [ClosedRange<UInt64>],
        ackDelay: NetworkDuration,
        in space: PacketNumberSpace,
        handshakeConfirmed: Bool,
        now: NetworkClock.Instant
    ) -> AckResult {
        var result = AckResult()
        self.congestion.bytesAcknowledged = 0
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
                    // Packets sent before the recovery period started don't grow the window
                    // (RFC 9002 Section 7.3.2).
                    if !self.congestion.inRecovery(sentTime: packet.timeSent) {
                        self.congestion.bytesAcknowledged &+= packet.size
                    }
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
        result.largestNewlyAcknowledgedTimeSent = largestNewlyAcked.timeSent

        // RTT sample (RFC 9002 Section 5.1).
        if largestNewlyAcked.packetNumber == largest, ackedAckEliciting {
            if self.firstRTTSampleTime == nil {
                self.firstRTTSampleTime = now
            }
            self.updateRTT(
                sample: largestNewlyAcked.timeSent.duration(to: now),
                ackDelay: ackDelay,
                handshakeConfirmed: handshakeConfirmed
            )
            result.rttSampled = true
        }

        var persistentCongestion = false
        result.lost = self.detectLostPackets(in: space, now: now, persistentCongestion: &persistentCongestion)
        if !result.lost.isEmpty {
            result.congestionLoss = self.onPacketsLost(
                result.lost,
                persistentCongestion: persistentCongestion,
                now: now
            )
        }

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
        // `sample - ackDelay >= minRTT`, without an addition that could overflow.
        if sample >= ackDelay && sample - ackDelay >= self.minRTT {
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
        var persistentCongestion = false
        return self.detectLostPackets(in: space, now: now, persistentCongestion: &persistentCongestion)
    }

    /// Declares the packets lost that the largest acknowledged one or the time leave behind
    /// (RFC 9002 Section 6.1), and finds whether they establish persistent congestion.
    private mutating func detectLostPackets(
        in space: PacketNumberSpace,
        now: NetworkClock.Instant,
        persistentCongestion: inout Bool
    ) -> [CoreSentPacket] {
        let index = Int(space.rawValue)
        guard let largestAcknowledged = self.spaces[index].largestAcknowledged else { return [] }
        self.spaces[index].lossTime = nil
        let lossDelay = self.lossDelay
        var lost: [CoreSentPacket] = []
        // Only packets up to the largest acknowledged one can be lost; they are at the front.
        let end = Self.firstIndex(in: self.spaces[index].sent, above: largestAcknowledged)
        var kept: [CoreSentPacket] = []
        var period = CorePersistentCongestionPeriod(
            duration: self.persistentCongestionDuration,
            firstRTTSampleTime: self.firstRTTSampleTime
        )
        for position in 0..<end {
            let packet = self.spaces[index].sent[position]
            let lostByTime = packet.timeSent.advanced(by: lossDelay) <= now
            let lostByCount = largestAcknowledged >= packet.packetNumber &+ Self.packetThreshold
            let isLost = lostByTime || lostByCount
            period.add(packet, lost: isLost)
            if isLost {
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
        persistentCongestion = period.isEstablished
        return lost
    }

    /// How long the lost packets must span for persistent congestion (RFC 9002 Section 7.6.1).
    var persistentCongestionDuration: NetworkDuration {
        self.probeTimeout(includingMaxAckDelay: true) * Int(Self.persistentCongestionThreshold)
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
            var persistentCongestion = false
            let lost = self.detectLostPackets(in: space, now: now, persistentCongestion: &persistentCongestion)
            if !lost.isEmpty {
                self.onPacketsLost(lost, persistentCongestion: persistentCongestion, now: now)
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
        let bytesInFlight = self.congestion.bytesInFlight
        self.congestion = CoreCongestionState(maxDatagramSize: self.congestion.maxDatagramSize)
        self.congestion.bytesInFlight = bytesInFlight
        self.controller = CoreCongestionController(self.controller.algorithm, state: &self.congestion)
        self.pacer?.reset(
                congestionWindow: self.congestion.congestionWindow,
                maxDatagramSize: self.congestion.maxDatagramSize
            )
    }

    /// Paces at the rate the congestion window allows per RTT, once it changed.
    private mutating func updatePacer() {
        guard self.pacer != nil else { return }
        self.pacer!.update(
            congestionWindow: self.congestion.congestionWindow,
            inSlowStart: self.congestion.inSlowStart,
            smoothedRTT: self.smoothedRTT,
            burstShift: self.controller.burstShift
        )
    }

    /// Grows the window by what the ACK frame acknowledged, unless it declared packets lost,
    /// and paces at the new window.
    mutating func onAckEnd(packetsLost: Bool, now: NetworkClock.Instant) {
        self.controller.onAckEnd(
            state: &self.congestion,
            packetsLost: packetsLost,
            smoothedRTT: self.smoothedRTT,
            now: now
        )
        self.congestion.bytesAcknowledged = 0
        self.updatePacer()
    }

    /// Reacts to packets declared lost. Returns whether any was a congestion signal: lost PMTUD
    /// probes are none (RFC 9000 Section 14.4).
    @discardableResult
    private mutating func onPacketsLost(
        _ lost: [CoreSentPacket],
        persistentCongestion: Bool,
        now: NetworkClock.Instant
    ) -> Bool {
        var lastSent: NetworkClock.Instant?
        for packet in lost where packet.isInFlight && !packet.isPMTUDProbe {
            if lastSent.map({ packet.timeSent > $0 }) ?? true {
                lastSent = packet.timeSent
            }
        }
        guard let lastSent else { return false }
        self.controller.onCongestionEvent(state: &self.congestion, sentTime: lastSent, now: now)
        if persistentCongestion {
            // RFC 9002 Section 7.6.2: the window collapses, and the next loss is a new congestion
            // event. min_rtt starts over from the latest sample (Section 5.2).
            self.controller.onPersistentCongestion(state: &self.congestion)
            self.congestion.recoveryStartTime = nil
            self.minRTT = self.latestRTT
            self.pacer?.reset(
                congestionWindow: self.congestion.congestionWindow,
                maxDatagramSize: self.congestion.maxDatagramSize
            )
        }
        return true
    }

    /// Feeds the ECN counts of an ACK frame to the controller, once the path is ECN-capable
    /// (RFC 9002 Section 7.1).
    mutating func onECNFeedback(_ feedback: CoreECNFeedback, now: NetworkClock.Instant) {
        self.controller.onECNFeedback(state: &self.congestion, feedback, smoothedRTT: self.smoothedRTT, now: now)
    }
}

/// The lost packets of one space, in packet number order, checked for persistent congestion
/// (RFC 9002 Section 7.6.2): two ack-eliciting packets declared lost, sent at least the
/// persistent congestion duration apart, with no packet in between acknowledged, all sent after
/// the first RTT sample.
@available(Network 0.1.0, *)
struct CorePersistentCongestionPeriod {
    let duration: NetworkDuration
    let firstRTTSampleTime: NetworkClock.Instant?
    private var start: NetworkClock.Instant?
    private var previousPacketNumber: UInt64?
    private(set) var isEstablished = false

    init(duration: NetworkDuration, firstRTTSampleTime: NetworkClock.Instant?) {
        self.duration = duration
        self.firstRTTSampleTime = firstRTTSampleTime
    }

    /// Adds the next packet of the space up to the largest acknowledged one, lost or still in
    /// flight.
    mutating func add(_ packet: CoreSentPacket, lost: Bool) {
        guard let firstRTTSampleTime = self.firstRTTSampleTime, !self.isEstablished else { return }
        if let previous = self.previousPacketNumber, packet.packetNumber != previous &+ 1 {
            // A packet in between is gone: acknowledged, or lost before. Either ends the period.
            self.start = nil
        }
        self.previousPacketNumber = packet.packetNumber
        guard lost, packet.isAckEliciting, !packet.isPMTUDProbe, packet.timeSent >= firstRTTSampleTime else {
            // Packets in flight in between don't end the period, nor do lost probes.
            return
        }
        if self.start == nil {
            self.start = packet.timeSent
        }
        if let start = self.start, start.duration(to: packet.timeSent) >= self.duration {
            self.isEstablished = true
        }
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
    /// allows so that pacing doesn't slow the window's growth. A burst is the rate shifted right
    /// by `burstShift`: Prague's are shorter, for the short L4S queues.
    mutating func update(
        congestionWindow: Int,
        inSlowStart: Bool,
        smoothedRTT: NetworkDuration,
        burstShift: UInt64 = CorePacer.burstShift
    ) {
        let microseconds = smoothedRTT.microseconds > 0 ? smoothedRTT.microseconds : Self.startupRTT.microseconds
        let window = UInt64(max(0, congestionWindow)) &* (inSlowStart ? 2 : 1)
        self.rate = window &* 1_000_000 / UInt64(microseconds)
        self.burstSize = Int(truncatingIfNeeded: self.rate >> burstShift)
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
