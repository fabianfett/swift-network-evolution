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

/// A network path of a connection, as the driver names it: a pair of local and remote addresses.
@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public struct CorePathID: Hashable, Sendable, CustomStringConvertible {
    public var rawValue: Int

    public init(_ rawValue: Int) {
        self.rawValue = rawValue
    }

    /// The path of the handshake.
    public static let initial = CorePathID(0)

    public var description: String { "path \(self.rawValue)" }
}

/// What the core knows about a path (RFC 9000 Sections 8.2 and 9).
@available(Network 0.1.0, *)
struct CorePath {
    let id: CorePathID
    var isValidated: Bool
    /// The peer's connection ID packets on this path go to, unless it is the active path, which
    /// uses `peerConnectionID`.
    var peerConnectionIDSequenceNumber: UInt64?
    /// The bytes received and sent on the path, which limit what goes out before it is validated.
    var bytesReceived = 0
    var bytesSent = 0
    /// The data of the PATH_CHALLENGE in flight, when it went out, and how many went out.
    var challenge: UInt64?
    var challengeDeadline: NetworkClock.Instant?
    var challengesSent = 0
    var challengeSentTime: NetworkClock.Instant?
    /// A PATH_CHALLENGE is due.
    var challengePending = false
    /// PATH_CHALLENGE data the peer sent on this path, to answer on it.
    var pendingResponses: [UInt64] = []
    /// This endpoint moves to the path once it is validated.
    var migrateWhenValidated = false
    var failed = false

    static let maximumChallenges = 3
    /// PATH_CHALLENGE data kept to answer; a flood of them keeps only the latest.
    static let maximumPendingResponses = 4

    init(id: CorePathID, isValidated: Bool) {
        self.id = id
        self.isValidated = isValidated
    }

    var isValidating: Bool {
        self.challengePending || self.challenge != nil
    }

    var hasProbingFramesToSend: Bool {
        self.challengePending || !self.pendingResponses.isEmpty
    }
}

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// The path packets go out on and the peer sends to.
    public var activePathID: CorePathID {
        self.activePath
    }

    /// Whether the path was validated.
    public func isPathValidated(_ path: CorePathID) -> Bool {
        self.paths[path]?.isValidated ?? false
    }

    /// The peer's connection ID packets on `path` are sent to.
    public func peerConnectionID(on path: CorePathID) -> QUICConnectionID? {
        if path == self.activePath { return self.peerConnectionID }
        guard let sequenceNumber = self.paths[path]?.peerConnectionIDSequenceNumber else { return nil }
        return self.connectionIDs.peer.first { $0.sequenceNumber == sequenceNumber }?.connectionID
    }

    /// A path other than the active one that has a probe to send, which ``send(into:on:now:)``
    /// takes next.
    public var pathWithProbeToSend: CorePathID? {
        guard !self.isClosingOrDraining, self.handshake.isComplete else { return nil }
        for (id, path) in self.paths where id != self.activePath && path.hasProbingFramesToSend {
            // A path that lost its connection ID to Retire Prior To gets another one.
            if self.peerConnectionID(on: id) != nil || self.hasUnusedPeerConnectionID,
                self.amplificationBudget(on: id) > 0
            {
                return id
            }
        }
        return nil
    }

    /// Validates `path` with PATH_CHALLENGE (RFC 9000 Section 8.2), which a client does before it
    /// migrates. Returns `false` if there is no unused connection ID of the peer for it, the
    /// handshake isn't confirmed, or the peer disabled migration.
    @discardableResult
    public mutating func probePath(_ path: CorePathID, now: NetworkClock.Instant) -> Bool {
        guard !self.isServer, self.isHandshakeConfirmed, !self.isClosingOrDraining, !self.peerDisabledMigration else {
            return false
        }
        if self.paths[path] == nil {
            self.paths[path] = CorePath(id: path, isValidated: false)
        }
        guard path != self.activePath else { return true }
        guard self.assignPeerConnectionID(to: path) else { return false }
        if !self.paths[path]!.isValidated {
            self.startValidation(of: path)
        }
        return true
    }

    /// Moves to `path`, validating it first if needed (RFC 9000 Section 9). Only a client
    /// migrates on its own.
    @discardableResult
    public mutating func migrate(to path: CorePathID, now: NetworkClock.Instant) -> Bool {
        guard path != self.activePath else { return true }
        guard self.probePath(path, now: now) else { return false }
        if self.paths[path]!.isValidated {
            self.makeActive(path, now: now)
        } else {
            self.paths[path]!.migrateWhenValidated = true
        }
        return true
    }

    /// Forgets a path the driver no longer uses, retiring the peer's connection ID on it.
    public mutating func forgetPath(_ path: CorePathID) {
        guard path != self.activePath, let removed = self.paths.removeValue(forKey: path) else { return }
        self.retirePathConnectionID(removed)
    }

    var peerDisabledMigration: Bool {
        self.peerTransportParameters?[.disableActiveMigration] != nil
    }

    // MARK: Validation

    mutating func startValidation(of path: CorePathID) {
        guard var state = self.paths[path], !state.isValidating else { return }
        state.challengesSent = 0
        state.challengePending = true
        state.failed = false
        self.paths[path] = state
    }

    /// The bytes that may still go out on `path` before it is validated: three times what
    /// arrived on it (RFC 9000 Section 8). A client limits nothing.
    func amplificationBudget(on path: CorePathID) -> Int {
        guard self.isServer, let state = self.paths[path], !state.isValidated else { return .max }
        return max(0, 3 &* state.bytesReceived &- state.bytesSent)
    }

    /// Gives `path` a connection ID of the peer that no other path uses. A zero-length one is
    /// shared.
    mutating func assignPeerConnectionID(to path: CorePathID) -> Bool {
        guard path != self.activePath else { return true }
        if self.paths[path]?.peerConnectionIDSequenceNumber != nil { return true }
        if self.peerConnectionID.length == 0 {
            self.paths[path]?.peerConnectionIDSequenceNumber = self.connectionIDs.currentPeerSequenceNumber
            return true
        }
        var inUse: Set<UInt64> = [self.connectionIDs.currentPeerSequenceNumber]
        for state in self.paths.values {
            if let sequenceNumber = state.peerConnectionIDSequenceNumber { inUse.insert(sequenceNumber) }
        }
        guard let unused = self.connectionIDs.peer.first(where: { !inUse.contains($0.sequenceNumber) }) else {
            self.log.error("No unused connection ID of the peer for \(path)")
            return false
        }
        self.paths[path]?.peerConnectionIDSequenceNumber = unused.sequenceNumber
        return true
    }

    var hasUnusedPeerConnectionID: Bool {
        var inUse: Set<UInt64> = [self.connectionIDs.currentPeerSequenceNumber]
        for state in self.paths.values {
            if let sequenceNumber = state.peerConnectionIDSequenceNumber { inUse.insert(sequenceNumber) }
        }
        return self.connectionIDs.peer.contains { !inUse.contains($0.sequenceNumber) }
    }

    /// Retires the peer's connection ID of a path that is gone, unless the active path uses it.
    mutating func retirePathConnectionID(_ state: CorePath) {
        guard let sequenceNumber = state.peerConnectionIDSequenceNumber,
            sequenceNumber != self.connectionIDs.currentPeerSequenceNumber,
            let entry = self.connectionIDs.peer.first(where: { $0.sequenceNumber == sequenceNumber })
        else {
            return
        }
        _ = self.retirePeerConnectionID(entry.connectionID)
    }

    /// A PATH_RESPONSE validates the path its PATH_CHALLENGE went out on, wherever it arrived
    /// (RFC 9000 Section 8.2.3).
    mutating func pathResponseReceived(_ data: UInt64, now: NetworkClock.Instant) {
        guard let (id, _) = self.paths.first(where: { $0.value.challenge == data }) else {
            self.log.debug("PATH_RESPONSE for no PATH_CHALLENGE")
            return
        }
        var state = self.paths[id]!
        state.challenge = nil
        state.challengeDeadline = nil
        state.challengePending = false
        let wasValidated = state.isValidated
        state.isValidated = true
        let migrates = state.migrateWhenValidated
        state.migrateWhenValidated = false
        self.paths[id] = state
        if !wasValidated {
            self.events.append(.pathValidated(id))
        }
        if migrates {
            self.makeActive(id, now: now)
        }
    }

    /// Resends PATH_CHALLENGE, or gives the path up, when the last one went unanswered.
    mutating func handlePathTimeouts(now: NetworkClock.Instant) {
        for (id, state) in self.paths {
            guard let deadline = state.challengeDeadline, now >= deadline else { continue }
            var state = state
            state.challenge = nil
            state.challengeDeadline = nil
            if state.challengesSent < CorePath.maximumChallenges {
                state.challengePending = true
                self.paths[id] = state
                continue
            }
            state.failed = true
            state.migrateWhenValidated = false
            self.paths[id] = state
            self.log.error("Validating \(id) failed")
            self.events.append(.pathFailed(id))
            if id == self.activePath, let fallback = self.paths.first(where: { $0.key != id && $0.value.isValidated }) {
                // RFC 9000 Section 9.3.2: back to the last validated path.
                self.makeActive(fallback.key, now: now)
            }
        }
    }

    var nextPathDeadline: NetworkClock.Instant? {
        self.paths.values.compactMap(\.challengeDeadline).min()
    }

    /// How long a PATH_CHALLENGE waits for its response (RFC 9000 Section 8.2.4).
    var pathValidationTimeout: NetworkDuration {
        max(self.recovery.probeTimeout(includingMaxAckDelay: true) * 3, .milliseconds(30))
    }

    // MARK: Migration

    /// The highest-numbered non-probing packet arrived on `path`. A server follows a client that
    /// moved to a new address there (RFC 9000 Section 9.3).
    mutating func nonProbingPacketArrived(on path: CorePathID, packetNumber: UInt64, now: NetworkClock.Instant) {
        if let largest = self.largestNonProbingPacketNumber, packetNumber <= largest { return }
        self.largestNonProbingPacketNumber = packetNumber
        guard self.isServer, path != self.activePath, self.isHandshakeConfirmed else { return }
        if self.paths[path]?.peerConnectionIDSequenceNumber == nil && self.hasUnusedPeerConnectionID {
            _ = self.assignPeerConnectionID(to: path)
        }
        // Without a spare one, a NAT rebinding keeps the current connection ID (RFC 9000
        // Section 9.5).
        self.log.info("The client moved to \(path)")
        self.makeActive(path, now: now)
        if !self.paths[path]!.isValidated {
            self.startValidation(of: path)
        }
    }

    /// Sends on `path` from now on.
    mutating func makeActive(_ path: CorePathID, now: NetworkClock.Instant) {
        guard path != self.activePath, let state = self.paths[path] else { return }
        let previous = self.activePath
        if let sequenceNumber = state.peerConnectionIDSequenceNumber,
            let entry = self.connectionIDs.peer.first(where: { $0.sequenceNumber == sequenceNumber })
        {
            // The previous path keeps the connection ID it used until it is forgotten.
            self.paths[previous]?.peerConnectionIDSequenceNumber = self.connectionIDs.currentPeerSequenceNumber
            self.switchPeerConnectionID(to: entry)
            self.paths[path]?.peerConnectionIDSequenceNumber = nil
        }
        self.activePath = path
        // RFC 9000 Section 9.4: the new path's congestion controller starts over.
        self.recovery.resetCongestionControl()
        // RFC 9000 Section 13.4.2: ECN is validated on each path.
        self.resetECNValidation()
        if !self.isServer {
            // The server only follows a non-probing packet.
            self.pingPending = true
        }
        self.events.append(.activePathChanged(path))
    }

    // MARK: Sending

    /// Writes the PATH_CHALLENGE and PATH_RESPONSE frames due on `path`. Returns whether any was
    /// written, as their datagram has to be at least 1200 bytes (RFC 9000 Section 8.2).
    mutating func writePathFrames(
        for path: CorePathID,
        into writer: inout CoreWriter,
        limit: Int,
        frames: inout [CoreSentFrame],
        isAckEliciting: inout Bool,
        now: NetworkClock.Instant
    ) -> Bool {
        guard var state = self.paths[path] else { return false }
        var wrote = false
        while let data = state.pendingResponses.first, writer.offset &+ 9 <= limit {
            guard writer.uint8(0x1b), writer.uint64(data) else { break }
            state.pendingResponses.removeFirst()
            frames.append(.pathResponse)
            isAckEliciting = true
            wrote = true
        }
        if state.challengePending, writer.offset &+ 9 <= limit {
            var generator = SystemRandomNumberGenerator()
            let data = UInt64.random(in: 0...UInt64.max, using: &generator)
            if writer.uint8(0x1a), writer.uint64(data) {
                state.challengePending = false
                state.challenge = data
                state.challengesSent &+= 1
                state.challengeSentTime = now
                // Each retry waits twice as long.
                state.challengeDeadline = now.advanced(
                    by: self.pathValidationTimeout * (1 << (state.challengesSent &- 1))
                )
                frames.append(.pathChallenge)
                isAckEliciting = true
                wrote = true
            }
        }
        self.paths[path] = state
        return wrote
    }
}

#endif
