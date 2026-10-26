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

/// The ECN counts of one packet number space: the packets that arrived with each codepoint, or
/// the counts the peer reported in ACK frames (RFC 9000 Section 13.4.1).
@available(Network 0.1.0, *)
struct CoreECNCounts: Equatable {
    var ect0: UInt64 = 0
    var ect1: UInt64 = 0
    var ce: UInt64 = 0

    var isZero: Bool {
        self.ect0 == 0 && self.ect1 == 0 && self.ce == 0
    }

    mutating func count(_ codepoint: IPProtocol.ECN) {
        switch codepoint {
        case .ect0: self.ect0 &+= 1
        case .ect1: self.ect1 &+= 1
        case .ce: self.ce &+= 1
        case .nonECT: break
        }
    }
}

/// ECN validation of the active path (RFC 9000 Section 13.4.2): whether the path carries the
/// ECN-capable codepoint this endpoint sets, and whether to keep setting it.
///
/// The first ten ack-eliciting packets are validation packets; if enough of them are lost before an
/// ACK frame confirmed the counts, the path drops ECN-capable packets. The counts it checks belong
/// to the packet number spaces, which a new path shares; the validation starts over on each path.
@available(Network 0.1.0, *)
struct CoreECNValidator {
    enum State: Equatable {
        /// This endpoint doesn't mark its packets.
        case disabled
        /// The validation packets go out marked; no ACK frame confirmed them yet.
        case probing
        /// An ACK frame confirmed some validation packets, and more go out.
        case probingValidated
        /// All validation packets went out; ack-eliciting packets go out marked until an ACK
        /// frame confirms them.
        case validating
        /// Validation succeeded: every packet goes out marked, and CE counts are congestion
        /// signals (RFC 9002 Section 7.1).
        case capable
        /// The peer's counts were wrong or missing.
        case unsupported
        /// Enough validation packets were lost that the path probably drops ECN-capable packets.
        case blackholed
        /// The path marked every ECN-capable packet CE.
        case manglingDetected

        /// Whether packets go out marked.
        var isMarking: Bool {
            switch self {
            case .probing, .probingValidated, .validating, .capable: return true
            case .disabled, .unsupported, .blackholed, .manglingDetected: return false
            }
        }
    }

    static let validationPacketCount = 10
    /// How many validation packets may be lost before the path counts as dropping ECN-capable
    /// packets. ECT(1) for L4S expects frequent marks and allows more.
    static let lostValidationPacketLimit = (ect0: 3, ect1: 10)

    private(set) var state: State
    let markingEnabled: Bool
    let useECT1: Bool
    private(set) var validationPacketsSent = 0
    private(set) var validationPacketsLost = 0

    init(markingEnabled: Bool, useECT1: Bool) {
        self.markingEnabled = markingEnabled
        self.useECT1 = useECT1
        self.state = markingEnabled ? .probing : .disabled
    }

    /// The codepoint of ECN-capable packets.
    var codepoint: IPProtocol.ECN {
        self.useECT1 ? .ect1 : .ect0
    }

    /// Starts over, for a new path.
    mutating func reset() {
        self = CoreECNValidator(markingEnabled: self.markingEnabled, useECT1: self.useECT1)
    }

    /// The codepoint of a datagram with `ackElicitingPackets` ack-eliciting packets, and whether
    /// they are validation packets. Until validation succeeded, only datagrams with an
    /// ack-eliciting packet are marked: the loss of the others would never be noticed.
    mutating func mark(ackElicitingPackets: Int) -> (codepoint: IPProtocol.ECN, isValidation: Bool) {
        switch self.state {
        case .probing, .probingValidated:
            guard ackElicitingPackets > 0 else { return (.nonECT, false) }
            self.validationPacketsSent &+= ackElicitingPackets
            if self.validationPacketsSent >= Self.validationPacketCount {
                self.state = .validating
            }
            return (self.codepoint, true)
        case .validating:
            return (ackElicitingPackets > 0 ? self.codepoint : .nonECT, false)
        case .capable:
            return (self.codepoint, false)
        case .disabled, .unsupported, .blackholed, .manglingDetected:
            return (.nonECT, false)
        }
    }

    /// A validation packet was declared lost.
    mutating func validationPacketLost() {
        self.validationPacketsLost &+= 1
        let limit = self.useECT1 ? Self.lostValidationPacketLimit.ect1 : Self.lostValidationPacketLimit.ect0
        if self.state == .probing || self.state == .validating, self.validationPacketsLost >= limit {
            self.state = .blackholed
        }
    }

    /// Validates the ECN counts of an ACK frame (RFC 9000 Section 13.4.2.1). Returns how many
    /// packets the peer newly reported CE.
    ///
    /// - Parameters:
    ///   - counts: The ACK frame's counts; `nil` for an ACK frame without them.
    ///   - newlyAcknowledged: The packets the frame newly acknowledged that went out marked.
    ///   - increasesLargestAcknowledged: Whether the frame raised the largest acknowledged packet
    ///     number. One that didn't may be reordered and can't fail validation.
    ///   - sent: The packets of the space that went out marked.
    ///   - feedback: The largest counts of the space the peer reported so far.
    mutating func validate(
        _ counts: CoreECNCounts?,
        newlyAcknowledged: UInt64,
        increasesLargestAcknowledged: Bool,
        sent: UInt64,
        feedback: inout CoreECNCounts
    ) -> UInt64 {
        guard increasesLargestAcknowledged, self.state.isMarking else { return 0 }
        guard let counts else {
            // Packets that went out marked are acknowledged without counts.
            if newlyAcknowledged > 0 {
                self.state = .unsupported
            }
            return 0
        }
        let marked = self.useECT1 ? counts.ect1 : counts.ect0
        let unexpected = self.useECT1 ? counts.ect0 : counts.ect1
        // A count of the codepoint this endpoint never sets means the path remarks packets.
        guard unexpected == 0 else {
            self.state = .unsupported
            return 0
        }
        // More packets reported ECN-capable or CE than went out marked.
        guard marked <= sent, counts.ce <= sent &- marked else {
            self.state = .unsupported
            return 0
        }
        // Counts never decrease; lower ones are from a reordered ACK frame.
        guard counts.ect0 >= feedback.ect0, counts.ect1 >= feedback.ect1, counts.ce >= feedback.ce else {
            return 0
        }
        if self.state == .validating, marked == 0, counts.ce > 0 {
            // Every packet that arrived was CE: the path rewrites the codepoint to CE.
            self.state = .manglingDetected
            return 0
        }
        let previouslyMarked = self.useECT1 ? feedback.ect1 : feedback.ect0
        let increase = (marked &- previouslyMarked) &+ (counts.ce &- feedback.ce)
        // The counts must cover the newly acknowledged packets, or the path cleared their marks.
        guard increase >= newlyAcknowledged else {
            self.state = .unsupported
            return 0
        }
        let newlyCE = counts.ce &- feedback.ce
        feedback = counts
        // Only an ACK frame for packets that went out marked confirms that the path carries them.
        if newlyAcknowledged > 0 {
            switch self.state {
            case .probing: self.state = .probingValidated
            case .validating: self.state = .capable
            default: break
            }
        }
        return newlyCE
    }
}

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// Marks the datagram just written, whose packets in the spaces of `spaces` (a bit per space)
    /// are the last ones sent there. All packets of a datagram share its codepoint.
    mutating func markDatagram(spaces: UInt8) -> IPProtocol.ECN {
        var ackElicitingPackets = 0
        for index in 0..<3 where spaces & (1 << index) != 0 {
            if self.recovery.spaces[index].sent.last?.isAckEliciting == true {
                ackElicitingPackets &+= 1
            }
        }
        let (codepoint, isValidation) = self.ecn.mark(ackElicitingPackets: ackElicitingPackets)
        guard codepoint != .nonECT else { return .nonECT }
        for index in 0..<3 where spaces & (1 << index) != 0 {
            let last = self.recovery.spaces[index].sent.count &- 1
            guard last >= 0 else { continue }
            self.recovery.spaces[index].sent[last].ecn = codepoint
            if isValidation && self.recovery.spaces[index].sent[last].isAckEliciting {
                self.recovery.spaces[index].sent[last].isECNValidation = true
            }
            self.recovery.spaces[index].ecnCapableSent &+= 1
            self.statistics.increment(codepoint == .ect1 ? .txECT1 : .txECT0)
            self.statistics.increment(.ecnCapablePacketsSent)
        }
        return codepoint
    }

    /// Counts the codepoint of a packet that arrived, for the ACK frames of its space. Returns
    /// whether it was CE, which is acknowledged right away (RFC 9000 Section 13.2.1).
    mutating func countReceivedECN(in space: PacketNumberSpace) -> Bool {
        let codepoint = self.receivingECN
        guard codepoint != .nonECT, self.configuration.ecnEchoEnabled else { return false }
        self.acks[space].ecnCounts.count(codepoint)
        switch codepoint {
        case .ect0: self.statistics.increment(.rxECT0)
        case .ect1: self.statistics.increment(.rxECT1)
        case .ce: self.statistics.increment(.rxECTCE)
        case .nonECT: break
        }
        return codepoint == .ce
    }

    /// Validates the ECN counts of an ACK frame, and reacts to new CE marks once the path is
    /// ECN-capable: like a loss, at most once per recovery period (RFC 9002 Sections 7.1 and B.7).
    mutating func processAckECN(
        _ counts: CoreECNCounts?,
        newlyAcknowledged: UInt64,
        increasesLargestAcknowledged: Bool,
        largestNewlyAcknowledgedTimeSent: NetworkClock.Instant?,
        in space: PacketNumberSpace,
        now: NetworkClock.Instant
    ) {
        self.statistics.increment(.ecnCapablePacketsAcknowledged, by: Int(truncatingIfNeeded: newlyAcknowledged))
        let index = Int(space.rawValue)
        let previousState = self.ecn.state
        let newlyCE = self.ecn.validate(
            counts,
            newlyAcknowledged: newlyAcknowledged,
            increasesLargestAcknowledged: increasesLargestAcknowledged,
            sent: self.recovery.spaces[index].ecnCapableSent,
            feedback: &self.recovery.spaces[index].ecnFeedback
        )
        if previousState != self.ecn.state {
            self.log.info("ECN validation: \(previousState) -> \(self.ecn.state)")
        }
        guard newlyCE > 0 else { return }
        self.statistics.increment(.ecnCapablePacketsMarked, by: Int(truncatingIfNeeded: newlyCE))
        if self.ecn.state == .capable, let sentTime = largestNewlyAcknowledgedTimeSent {
            self.recovery.onCongestionExperienced(sentTime: sentTime, now: now)
        }
    }

    /// Starts ECN validation over, for a new active path (RFC 9000 Section 13.4.2). Packets in
    /// flight on the old path are no longer validation packets of this one.
    mutating func resetECNValidation() {
        self.ecn.reset()
        let index = Int(PacketNumberSpace.applicationData.rawValue)
        for position in self.recovery.spaces[index].sent.indices
        where self.recovery.spaces[index].sent[position].isECNValidation {
            self.recovery.spaces[index].sent[position].isECNValidation = false
        }
    }
}

#endif
