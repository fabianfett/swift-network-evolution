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
    /// The path MTU discovery of the path, once it was active after the handshake.
    var pmtud: CorePMTUD?
    /// The MTU of the path's interface, if the driver told; otherwise the configuration's.
    var interfaceMTU: Int?

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

/// The paths of a connection, one to a few and nearly always one, and which of them is active.
///
/// A dictionary's getter copies the whole path on every read, and each lookup hashes; at this size
/// a linear search is cheaper, and `self[index]` reads and changes a path in place. An index stays
/// valid until a path is added or removed, which only `receive(_:on:ecn:now:)`, `probePath(_:now:)`,
/// `setInterfaceMTU(_:on:)` and `forgetPath(_:)` do. The paths keep the order they were added in.
@available(Network 0.1.0, *)
struct CorePathTable {
    private var storage: [CorePath]
    /// The position of the active path, which is always in the table.
    private(set) var activeIndex: Int

    /// The handshake's path, validated and active.
    init() {
        self.storage = [CorePath(id: .initial, isValidated: true)]
        self.activeIndex = 0
    }

    var indices: Range<Int> {
        self.storage.indices
    }

    /// The path at `index`, read and changed in place.
    subscript(index: Int) -> CorePath {
        _read { yield self.storage[index] }
        _modify { yield &self.storage[index] }
    }

    /// The active path, read and changed in place.
    var active: CorePath {
        _read { yield self.storage[self.activeIndex] }
        _modify { yield &self.storage[self.activeIndex] }
    }

    var activeID: CorePathID {
        self.storage[self.activeIndex].id
    }

    /// A copy of path `id`, for tests; the core reads in place through ``index(of:)``.
    subscript(id: CorePathID) -> CorePath? {
        self.index(of: id).map { self.storage[$0] }
    }

    /// The position of path `id`; the active path is looked at first.
    func index(of id: CorePathID) -> Int? {
        if self.storage[self.activeIndex].id == id { return self.activeIndex }
        return self.firstIndex { $0.id == id }
    }

    /// The position of the first path, in the order they were added, that `predicate` accepts.
    func firstIndex(where predicate: (CorePath) -> Bool) -> Int? {
        for index in self.storage.indices where predicate(self.storage[index]) {
            return index
        }
        return nil
    }

    /// The position of path `id`, which is added, not validated, if it is new.
    mutating func indexAdding(_ id: CorePathID) -> Int {
        if let index = self.index(of: id) { return index }
        self.storage.append(CorePath(id: id, isValidated: false))
        return self.storage.endIndex &- 1
    }

    /// Removes the path at `index`, which must not be the active one.
    mutating func remove(at index: Int) -> CorePath {
        precondition(index != self.activeIndex, "The active path can't be removed")
        let removed = self.storage.remove(at: index)
        if index < self.activeIndex {
            self.activeIndex &-= 1
        }
        return removed
    }

    /// Makes the path at `index` the active one.
    mutating func makeActive(at index: Int) {
        precondition(self.storage.indices.contains(index), "No path at \(index)")
        self.activeIndex = index
    }
}

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// The path packets go out on and the peer sends to.
    public var activePathID: CorePathID {
        self.activePath
    }

    /// The path packets go out on and the peer sends to.
    var activePath: CorePathID {
        self.paths.activeID
    }

    /// Whether the path was validated.
    public func isPathValidated(_ path: CorePathID) -> Bool {
        guard let index = self.paths.index(of: path) else { return false }
        return self.paths[index].isValidated
    }

    /// The peer's connection ID packets on `path` are sent to.
    public func peerConnectionID(on path: CorePathID) -> QUICConnectionID? {
        if path == self.activePath { return self.peerConnectionID }
        guard let index = self.paths.index(of: path),
            let sequenceNumber = self.paths[index].peerConnectionIDSequenceNumber
        else {
            return nil
        }
        return self.connectionIDs.peer.first { $0.sequenceNumber == sequenceNumber }?.connectionID
    }

    /// A path other than the active one that has a probe to send, which ``send(into:on:now:)``
    /// takes next. The paths are looked at in the order they were added.
    public var pathWithProbeToSend: CorePathID? {
        guard !self.isClosingOrDraining, self.handshake.isComplete else { return nil }
        for index in self.paths.indices
        where index != self.paths.activeIndex && self.paths[index].hasProbingFramesToSend {
            let id = self.paths[index].id
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
        let index = self.paths.indexAdding(path)
        guard index != self.paths.activeIndex else { return true }
        guard self.assignPeerConnectionID(to: path) else { return false }
        if !self.paths[index].isValidated {
            self.startValidation(of: path)
        }
        return true
    }

    /// Moves to `path`, validating it first if needed (RFC 9000 Section 9). Only a client
    /// migrates on its own.
    @discardableResult
    public mutating func migrate(to path: CorePathID, now: NetworkClock.Instant) -> Bool {
        guard path != self.activePath else { return true }
        guard self.probePath(path, now: now), let index = self.paths.index(of: path) else { return false }
        if self.paths[index].isValidated {
            self.makeActive(path, now: now)
        } else {
            self.paths[index].migrateWhenValidated = true
        }
        return true
    }

    /// Forgets a path the driver no longer uses, retiring the peer's connection ID on it.
    public mutating func forgetPath(_ path: CorePathID) {
        guard let index = self.paths.index(of: path), index != self.paths.activeIndex else { return }
        let removed = self.paths.remove(at: index)
        self.retirePathConnectionID(removed)
    }

    var peerDisabledMigration: Bool {
        self.peerTransportParameters?[.disableActiveMigration] != nil
    }

    // MARK: Validation

    mutating func startValidation(of path: CorePathID) {
        guard let index = self.paths.index(of: path), !self.paths[index].isValidating else { return }
        self.paths[index].challengesSent = 0
        self.paths[index].challengePending = true
        self.paths[index].failed = false
    }

    /// The bytes that may still go out on `path` before it is validated: three times what
    /// arrived on it (RFC 9000 Section 8). A client limits nothing.
    func amplificationBudget(on path: CorePathID) -> Int {
        guard self.isServer, let index = self.paths.index(of: path), !self.paths[index].isValidated else {
            return .max
        }
        return max(0, 3 &* self.paths[index].bytesReceived &- self.paths[index].bytesSent)
    }

    /// The sequence numbers of the peer's connection IDs that a path or the active one uses.
    var peerConnectionIDsInUse: Set<UInt64> {
        var inUse: Set<UInt64> = [self.connectionIDs.currentPeerSequenceNumber]
        for index in self.paths.indices {
            if let sequenceNumber = self.paths[index].peerConnectionIDSequenceNumber { inUse.insert(sequenceNumber) }
        }
        return inUse
    }

    /// Gives `path` a connection ID of the peer that no other path uses. A zero-length one is
    /// shared.
    mutating func assignPeerConnectionID(to path: CorePathID) -> Bool {
        guard path != self.activePath else { return true }
        // Every caller knows the path already.
        guard let index = self.paths.index(of: path) else { return false }
        if self.paths[index].peerConnectionIDSequenceNumber != nil { return true }
        if self.peerConnectionID.length == 0 {
            self.paths[index].peerConnectionIDSequenceNumber = self.connectionIDs.currentPeerSequenceNumber
            return true
        }
        let inUse = self.peerConnectionIDsInUse
        guard let unused = self.connectionIDs.peer.first(where: { !inUse.contains($0.sequenceNumber) }) else {
            self.log.error("No unused connection ID of the peer for \(path)")
            return false
        }
        self.paths[index].peerConnectionIDSequenceNumber = unused.sequenceNumber
        return true
    }

    var hasUnusedPeerConnectionID: Bool {
        let inUse = self.peerConnectionIDsInUse
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
        guard let index = self.paths.firstIndex(where: { $0.challenge == data }) else {
            self.log.debug("PATH_RESPONSE for no PATH_CHALLENGE")
            return
        }
        let id = self.paths[index].id
        self.paths[index].challenge = nil
        self.paths[index].challengeDeadline = nil
        self.paths[index].challengePending = false
        let wasValidated = self.paths[index].isValidated
        self.paths[index].isValidated = true
        let migrates = self.paths[index].migrateWhenValidated
        self.paths[index].migrateWhenValidated = false
        if !wasValidated {
            self.events.append(.pathValidated(id))
        }
        if migrates {
            self.makeActive(id, now: now)
        }
    }

    /// Resends PATH_CHALLENGE, or gives the path up, when the last one went unanswered.
    mutating func handlePathTimeouts(now: NetworkClock.Instant) {
        // `makeActive` adds and removes no path, so the indices hold.
        for index in self.paths.indices {
            guard let deadline = self.paths[index].challengeDeadline, now >= deadline else { continue }
            self.paths[index].challenge = nil
            self.paths[index].challengeDeadline = nil
            if self.paths[index].challengesSent < CorePath.maximumChallenges {
                self.paths[index].challengePending = true
                continue
            }
            self.paths[index].failed = true
            self.paths[index].migrateWhenValidated = false
            let id = self.paths[index].id
            self.log.error("Validating \(id) failed")
            self.events.append(.pathFailed(id))
            if index == self.paths.activeIndex,
                let fallback = self.paths.firstIndex(where: { $0.id != id && $0.isValidated })
            {
                // RFC 9000 Section 9.3.2: back to the last validated path; of several, the one
                // added first.
                self.makeActive(self.paths[fallback].id, now: now)
            }
        }
    }

    var nextPathDeadline: NetworkClock.Instant? {
        var earliest: NetworkClock.Instant?
        for index in self.paths.indices {
            guard let deadline = self.paths[index].challengeDeadline else { continue }
            if let current = earliest, current <= deadline { continue }
            earliest = deadline
        }
        return earliest
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
        guard self.isServer, path != self.activePath, self.isHandshakeConfirmed,
            let index = self.paths.index(of: path)
        else {
            return
        }
        if self.paths[index].peerConnectionIDSequenceNumber == nil && self.hasUnusedPeerConnectionID {
            _ = self.assignPeerConnectionID(to: path)
        }
        // Without a spare one, a NAT rebinding keeps the current connection ID (RFC 9000
        // Section 9.5).
        self.log.info("The client moved to \(path)")
        self.makeActive(path, now: now)
        if !self.paths[index].isValidated {
            self.startValidation(of: path)
        }
    }

    /// Sends on `path` from now on.
    mutating func makeActive(_ path: CorePathID, now: NetworkClock.Instant) {
        guard let index = self.paths.index(of: path), index != self.paths.activeIndex else { return }
        let previous = self.paths.activeIndex
        if let sequenceNumber = self.paths[index].peerConnectionIDSequenceNumber,
            let entry = self.connectionIDs.peer.first(where: { $0.sequenceNumber == sequenceNumber })
        {
            // The previous path keeps the connection ID it used until it is forgotten.
            self.paths[previous].peerConnectionIDSequenceNumber = self.connectionIDs.currentPeerSequenceNumber
            self.switchPeerConnectionID(to: entry)
            self.paths[index].peerConnectionIDSequenceNumber = nil
        }
        self.paths.makeActive(at: index)
        // The new path carries what its PMTUD found, the base size before; its search starts
        // over (RFC 9000 Section 14.2).
        self.setMaxDatagramSize(self.paths[index].pmtud?.maxDatagramSize ?? self.configuration.maxDatagramSize)
        self.pmtudLargePacketsLost = 0
        // RFC 9000 Section 9.4: the new path's congestion controller starts over.
        self.recovery.resetCongestionControl()
        self.startPMTUD()
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
        guard let index = self.paths.index(of: path) else { return false }
        var wrote = false
        while let data = self.paths[index].pendingResponses.first, writer.offset &+ 9 <= limit {
            guard writer.uint8(0x1b), writer.uint64(data) else { break }
            self.paths[index].pendingResponses.removeFirst()
            frames.append(.pathResponse)
            isAckEliciting = true
            wrote = true
        }
        if self.paths[index].challengePending, writer.offset &+ 9 <= limit {
            var generator = SystemRandomNumberGenerator()
            let data = UInt64.random(in: 0...UInt64.max, using: &generator)
            if writer.uint8(0x1a), writer.uint64(data) {
                let timeout = self.pathValidationTimeout
                self.paths[index].challengePending = false
                self.paths[index].challenge = data
                self.paths[index].challengesSent &+= 1
                self.paths[index].challengeSentTime = now
                // Each retry waits twice as long.
                self.paths[index].challengeDeadline = now.advanced(
                    by: timeout * (1 << (self.paths[index].challengesSent &- 1))
                )
                frames.append(.pathChallenge)
                isAckEliciting = true
                wrote = true
            }
        }
        return wrote
    }
}

#endif
