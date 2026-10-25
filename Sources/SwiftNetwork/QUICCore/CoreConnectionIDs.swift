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

/// The connection IDs of both endpoints (RFC 9000 Section 5.1).
@available(Network 0.1.0, *)
struct CoreConnectionIDs {
    struct Entry: Equatable {
        var sequenceNumber: UInt64
        var connectionID: QUICConnectionID
        /// `nil` for a connection ID of the handshake whose token the peer didn't send.
        var token: QUICStatelessResetToken?
    }

    /// The connection IDs this endpoint issued and the peer didn't retire, oldest first.
    var local: [Entry]
    var nextLocalSequenceNumber: UInt64 = 1
    /// The sequence numbers of local connection IDs to announce in NEW_CONNECTION_ID frames.
    var newConnectionIDsPending: [UInt64] = []
    /// The local connection IDs the peer sent packets to.
    var usedLocalSequenceNumbers: Set<UInt64> = [0]

    /// The peer's connection IDs this endpoint didn't retire, oldest first.
    var peer: [Entry]
    /// The one this endpoint sends to.
    var currentPeerSequenceNumber: UInt64 = 0
    /// The largest Retire Prior To the peer sent.
    var retirePriorTo: UInt64 = 0
    /// The sequence numbers of peer connection IDs to retire with RETIRE_CONNECTION_ID frames.
    var retireConnectionIDsPending: [UInt64] = []

    init(local: QUICConnectionID, localToken: QUICStatelessResetToken?, peer: QUICConnectionID) {
        self.local = [Entry(sequenceNumber: 0, connectionID: local, token: localToken)]
        self.peer = [Entry(sequenceNumber: 0, connectionID: peer, token: nil)]
    }

    var peerStatelessResetTokens: [QUICStatelessResetToken] {
        self.peer.compactMap(\.token)
    }

    func localEntry(for connectionID: QUICConnectionID) -> Entry? {
        self.local.first { $0.connectionID == connectionID }
    }
}

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// The connection IDs this endpoint keeps for the peer to use, besides the handshake's.
    var localConnectionIDTarget: Int {
        min(self.peerActiveConnectionIDLimit, self.configuration.maxIssuedConnectionIDs)
    }

    /// Issues a connection ID to the peer. Returns `false` when the peer's
    /// active_connection_id_limit is reached, this endpoint uses zero-length connection IDs, or
    /// the connection ID is in use.
    @discardableResult
    public mutating func issueConnectionID(
        _ connectionID: QUICConnectionID,
        statelessResetToken: QUICStatelessResetToken
    ) -> Bool {
        guard self.handshake.isComplete, !self.isClosingOrDraining, self.localConnectionID.length > 0,
            self.connectionIDs.local.count < self.peerActiveConnectionIDLimit,
            self.connectionIDs.localEntry(for: connectionID) == nil
        else {
            return false
        }
        let sequenceNumber = self.connectionIDs.nextLocalSequenceNumber
        self.connectionIDs.nextLocalSequenceNumber &+= 1
        self.connectionIDs.local.append(
            CoreConnectionIDs.Entry(
                sequenceNumber: sequenceNumber,
                connectionID: connectionID,
                token: statelessResetToken
            )
        )
        self.connectionIDs.newConnectionIDsPending.append(sequenceNumber)
        self.events.append(
            .newLocalConnectionID(
                sequenceNumber: sequenceNumber,
                connectionID,
                statelessResetToken: statelessResetToken
            )
        )
        return true
    }

    /// Issues random connection IDs up to the target, if this endpoint does so on its own.
    mutating func issueConnectionIDsIfNeeded() {
        guard self.configuration.automaticallyIssueConnectionIDs else { return }
        let length = self.localConnectionID.length
        while self.connectionIDs.local.count < self.localConnectionIDTarget {
            guard self.issueConnectionID(QUICConnectionID(length), statelessResetToken: QUICStatelessResetToken())
            else {
                return
            }
        }
    }

    /// Retires one of the peer's connection IDs, sending RETIRE_CONNECTION_ID. Retiring the one
    /// in use switches to another; returns `false` if there is none, or the ID is unknown.
    @discardableResult
    public mutating func retirePeerConnectionID(_ connectionID: QUICConnectionID) -> Bool {
        guard !self.isClosingOrDraining,
            let index = self.connectionIDs.peer.firstIndex(where: { $0.connectionID == connectionID })
        else {
            return false
        }
        let entry = self.connectionIDs.peer[index]
        if entry.sequenceNumber == self.connectionIDs.currentPeerSequenceNumber {
            guard let replacement = self.connectionIDs.peer.first(where: { $0.sequenceNumber != entry.sequenceNumber })
            else {
                return false
            }
            self.switchPeerConnectionID(to: replacement)
        }
        self.connectionIDs.peer.remove(at: index)
        self.connectionIDs.retireConnectionIDsPending.append(entry.sequenceNumber)
        self.events.append(.retiredPeerConnectionID(entry.connectionID, statelessResetToken: entry.token))
        return true
    }

    mutating func switchPeerConnectionID(to entry: CoreConnectionIDs.Entry) {
        self.connectionIDs.currentPeerSequenceNumber = entry.sequenceNumber
        self.peerConnectionID = entry.connectionID
    }

    /// The handshake replaced the peer's connection ID: a client learns the server's from its
    /// first packet, or from a Retry.
    mutating func handshakePeerConnectionIDChanged(_ connectionID: QUICConnectionID) {
        self.peerConnectionID = connectionID
        if let index = self.connectionIDs.peer.firstIndex(where: { $0.sequenceNumber == 0 }) {
            self.connectionIDs.peer[index].connectionID = connectionID
        }
    }

    // MARK: Receiving

    /// NEW_CONNECTION_ID (RFC 9000 Section 19.15).
    mutating func processNewConnectionID(
        sequenceNumber: UInt64,
        retirePriorTo: UInt64,
        connectionID: QUICConnectionID,
        token: QUICStatelessResetToken,
        now: NetworkClock.Instant
    ) {
        guard self.peerConnectionID.length > 0 else {
            self.closeWithError(
                CoreTransportError.protocolViolation,
                frameType: 0x18,
                reason: "NEW_CONNECTION_ID with a zero-length connection ID",
                now: now
            )
            return
        }
        guard retirePriorTo <= sequenceNumber else {
            self.closeWithError(
                CoreTransportError.frameEncodingError,
                frameType: 0x18,
                reason: "Retire Prior To above the sequence number",
                now: now
            )
            return
        }
        var isRepeat = false
        if let existing = self.connectionIDs.peer.first(where: {
            $0.sequenceNumber == sequenceNumber || $0.connectionID == connectionID
        }) {
            // A retransmission repeats it; anything else is a violation.
            guard existing.sequenceNumber == sequenceNumber, existing.connectionID == connectionID,
                existing.token == nil || existing.token == token
            else {
                self.closeWithError(
                    CoreTransportError.protocolViolation,
                    frameType: 0x18,
                    reason: "NEW_CONNECTION_ID reuses a connection ID or sequence number",
                    now: now
                )
                return
            }
            isRepeat = true
        }
        // Retire Prior To applies before the new connection ID is added.
        if retirePriorTo > self.connectionIDs.retirePriorTo {
            self.connectionIDs.retirePriorTo = retirePriorTo
            var kept: [CoreConnectionIDs.Entry] = []
            for entry in self.connectionIDs.peer {
                if entry.sequenceNumber < retirePriorTo {
                    self.connectionIDs.retireConnectionIDsPending.append(entry.sequenceNumber)
                    self.events.append(.retiredPeerConnectionID(entry.connectionID, statelessResetToken: entry.token))
                } else {
                    kept.append(entry)
                }
            }
            self.connectionIDs.peer = kept
            for (id, path) in self.paths {
                if let sequenceNumber = path.peerConnectionIDSequenceNumber, sequenceNumber < retirePriorTo {
                    // The path picks another one before it sends again.
                    self.paths[id]?.peerConnectionIDSequenceNumber = nil
                }
            }
        }
        if sequenceNumber < self.connectionIDs.retirePriorTo {
            // Already retired by an earlier Retire Prior To: retire it right away.
            if !self.connectionIDs.retireConnectionIDsPending.contains(sequenceNumber) {
                self.connectionIDs.retireConnectionIDsPending.append(sequenceNumber)
            }
        } else if !isRepeat {
            self.connectionIDs.peer.append(
                CoreConnectionIDs.Entry(sequenceNumber: sequenceNumber, connectionID: connectionID, token: token)
            )
            self.events.append(
                .newPeerConnectionID(sequenceNumber: sequenceNumber, connectionID, statelessResetToken: token)
            )
        }
        // RFC 9000 Section 5.1.1: more than we allowed is CONNECTION_ID_LIMIT_ERROR; so are more
        // retirements than we keep track of (Section 5.1.2).
        let limit = Int(self.configuration.activeConnectionIDLimit)
        guard self.connectionIDs.peer.count <= limit,
            self.connectionIDs.retireConnectionIDsPending.count <= 2 &* limit
        else {
            self.closeWithError(
                CoreTransportError.connectionIDLimitError,
                frameType: 0x18,
                reason: "Too many connection IDs",
                now: now
            )
            return
        }
        if !self.connectionIDs.peer.contains(where: {
            $0.sequenceNumber == self.connectionIDs.currentPeerSequenceNumber
        }),
            let replacement = self.connectionIDs.peer.first
        {
            // The one in use was retired.
            self.switchPeerConnectionID(to: replacement)
        }
    }

    /// RETIRE_CONNECTION_ID (RFC 9000 Section 19.16).
    mutating func processRetireConnectionID(
        sequenceNumber: UInt64,
        packetDestination: QUICConnectionID?,
        now: NetworkClock.Instant
    ) {
        guard self.localConnectionID.length > 0 else {
            self.closeWithError(
                CoreTransportError.protocolViolation,
                frameType: 0x19,
                reason: "RETIRE_CONNECTION_ID with a zero-length connection ID",
                now: now
            )
            return
        }
        guard sequenceNumber < self.connectionIDs.nextLocalSequenceNumber else {
            self.closeWithError(
                CoreTransportError.protocolViolation,
                frameType: 0x19,
                reason: "RETIRE_CONNECTION_ID for a connection ID never issued",
                now: now
            )
            return
        }
        guard let index = self.connectionIDs.local.firstIndex(where: { $0.sequenceNumber == sequenceNumber }) else {
            // Retired before.
            return
        }
        let entry = self.connectionIDs.local[index]
        guard entry.connectionID != packetDestination else {
            self.closeWithError(
                CoreTransportError.protocolViolation,
                frameType: 0x19,
                reason: "RETIRE_CONNECTION_ID for the connection ID of its packet",
                now: now
            )
            return
        }
        self.connectionIDs.local.remove(at: index)
        self.connectionIDs.newConnectionIDsPending.removeAll { $0 == sequenceNumber }
        self.events.append(.retiredLocalConnectionID(entry.connectionID))
        self.issueConnectionIDsIfNeeded()
    }

    /// A short header packet arrived for `connectionID`. Returns `false` if it isn't one of ours.
    ///
    /// The first packet to a new connection ID makes this endpoint switch to a new one of the
    /// peer's too, so the two can't be linked, and issues a replacement.
    mutating func shortHeaderPacketArrived(for connectionID: QUICConnectionID) -> Bool {
        guard let entry = self.connectionIDs.localEntry(for: connectionID) else { return false }
        guard self.connectionIDs.usedLocalSequenceNumbers.insert(entry.sequenceNumber).inserted else {
            return true
        }
        // A packet on another path is a migration; that path gets a connection ID of its own.
        let usedByPaths = Set(self.paths.values.compactMap(\.peerConnectionIDSequenceNumber))
        if self.receivingPath == self.activePath,
            let unused = self.connectionIDs.peer.first(where: {
                $0.sequenceNumber > self.connectionIDs.currentPeerSequenceNumber
                    && !usedByPaths.contains($0.sequenceNumber)
            })
        {
            self.switchPeerConnectionID(to: unused)
        }
        self.issueConnectionIDsIfNeeded()
        return true
    }

    // MARK: Sending

    /// Writes pending NEW_CONNECTION_ID and RETIRE_CONNECTION_ID frames.
    mutating func writeConnectionIDFrames(
        into writer: inout CoreWriter,
        limit: Int,
        frames: inout [CoreSentFrame],
        isAckEliciting: inout Bool
    ) {
        while let sequenceNumber = self.connectionIDs.newConnectionIDsPending.first {
            guard let entry = self.connectionIDs.local.first(where: { $0.sequenceNumber == sequenceNumber }),
                let token = entry.token
            else {
                self.connectionIDs.newConnectionIDsPending.removeFirst()
                continue
            }
            let length =
                1 &+ CoreWriter.vleLength(sequenceNumber) &+ 1 &+ 1 &+ entry.connectionID.length
                &+ QUICStatelessResetToken.size
            guard writer.offset &+ length <= limit else { break }
            guard writer.vle(0x18), writer.vle(sequenceNumber), writer.vle(0),
                writer.uint8(UInt8(entry.connectionID.length)),
                writer.bytes(
                    entry.connectionID.connectionIDStorage.span.bytes.extracting(0..<entry.connectionID.length)
                ),
                writer.bytes(token.token.span.bytes)
            else {
                break
            }
            self.connectionIDs.newConnectionIDsPending.removeFirst()
            frames.append(.newConnectionID(sequenceNumber: sequenceNumber))
            isAckEliciting = true
        }
        while let sequenceNumber = self.connectionIDs.retireConnectionIDsPending.first {
            guard writer.offset &+ 1 &+ CoreWriter.vleLength(sequenceNumber) <= limit,
                writer.vle(0x19), writer.vle(sequenceNumber)
            else {
                break
            }
            self.connectionIDs.retireConnectionIDsPending.removeFirst()
            frames.append(.retireConnectionID(sequenceNumber: sequenceNumber))
            isAckEliciting = true
        }
    }

    var hasConnectionIDFramesToSend: Bool {
        !self.connectionIDs.newConnectionIDsPending.isEmpty || !self.connectionIDs.retireConnectionIDsPending.isEmpty
    }

    /// A packet with NEW_CONNECTION_ID or RETIRE_CONNECTION_ID was lost: send them again.
    mutating func connectionIDFrameLost(_ frame: CoreSentFrame) {
        switch frame {
        case .newConnectionID(let sequenceNumber):
            if self.connectionIDs.local.contains(where: { $0.sequenceNumber == sequenceNumber }),
                !self.connectionIDs.newConnectionIDsPending.contains(sequenceNumber)
            {
                self.connectionIDs.newConnectionIDsPending.append(sequenceNumber)
            }
        case .retireConnectionID(let sequenceNumber):
            if !self.connectionIDs.retireConnectionIDsPending.contains(sequenceNumber) {
                self.connectionIDs.retireConnectionIDsPending.append(sequenceNumber)
            }
        default:
            break
        }
    }
}

#endif
