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

/// One QUIC stream inside the state machine.
@available(Network 0.1.0, *)
struct CoreStream {
    let id: UInt64
    let canSend: Bool
    let canReceive: Bool

    var send = CoreSendBuffer()
    var receive = CoreReceiveBuffer()

    /// The peer's limit on the bytes we may send (MAX_STREAM_DATA).
    var sendLimit: UInt64
    /// The limit on the bytes the peer may send that we advertised.
    var receiveLimit: UInt64
    /// The receive window we keep open ahead of the read offset.
    let receiveWindow: UInt64
    /// A MAX_STREAM_DATA frame is due.
    var maxStreamDataPending = false
    /// A STREAM_DATA_BLOCKED frame is due.
    var dataBlockedPending = false
    var dataBlockedSentAt: UInt64?

    /// The error code of our RESET_STREAM, once the application reset the stream.
    var resetCode: UInt64?
    var resetPending = false
    var resetAcknowledged = false
    /// The error code of our STOP_SENDING.
    var stopSendingCode: UInt64?
    var stopSendingPending = false

    /// The error code of the peer's RESET_STREAM.
    var peerResetCode: UInt64?
    /// The error code of the peer's STOP_SENDING.
    var peerStopSendingCode: UInt64?

    /// Whether the readable event was reported since data last arrived.
    var readableReported = false
    /// Whether the application has to be told it can write again.
    var writableBlocked = false

    init(id: UInt64, canSend: Bool, canReceive: Bool, sendLimit: UInt64, receiveWindow: UInt64) {
        self.id = id
        self.canSend = canSend
        self.canReceive = canReceive
        self.sendLimit = sendLimit
        self.receiveWindow = receiveWindow
        self.receiveLimit = receiveWindow
    }

    /// The bytes the application may still enqueue before the stream's send limit is reached.
    var sendCapacity: Int {
        guard self.canSend, self.resetCode == nil, !self.send.isFinished else { return 0 }
        let limit = self.sendLimit
        let written = self.send.writeOffset
        return limit > written ? Int(min(limit &- written, UInt64(Int.max))) : 0
    }

    /// Whether the stream has frames to send.
    var hasPendingFrames: Bool {
        (self.canSend && self.resetCode == nil && self.send.hasDataToSend && self.hasSendCredit)
            || self.maxStreamDataPending || self.resetPending || self.stopSendingPending
            || self.dataBlockedPending
    }

    var hasSendCredit: Bool {
        self.send.hasRetransmission || self.send.sendOffset < self.sendLimit
            || (self.send.isFinished && !self.send.finSent && self.send.unsentCount == 0)
    }

    /// Whether both directions are done and the stream can be forgotten.
    var isClosed: Bool {
        let sendDone =
            !self.canSend || self.send.isFullyAcknowledged || (self.resetCode != nil && self.resetAcknowledged)
        let receiveDone = !self.canReceive || self.receive.isFinishedReading || self.peerResetCode != nil
        return sendDone && receiveDone
    }

    /// Grows the advertised receive limit once the application consumed half of the window.
    mutating func updateReceiveLimit() -> Bool {
        guard self.canReceive, self.receive.finalSize == nil, self.peerResetCode == nil else { return false }
        let target = self.receive.readOffset &+ self.receiveWindow
        if target &- self.receiveLimit >= self.receiveWindow / 2 {
            self.receiveLimit = target
            self.maxStreamDataPending = true
            return true
        }
        return false
    }
}

/// The streams of a connection, keyed by stream ID.
@available(Network 0.1.0, *)
struct CoreStreamMap {
    let isServer: Bool
    var streams: [UInt64: CoreStream] = [:]

    /// Streams with frames to send, in the order they asked.
    private(set) var sendQueue = Deque<UInt64>()
    private var queued = Set<UInt64>()

    /// The next stream IDs we open.
    private var nextLocalBidirectional: UInt64
    private var nextLocalUnidirectional: UInt64
    /// The peer's limits on the streams we open (MAX_STREAMS).
    var peerMaxStreamsBidirectional: UInt64 = 0
    var peerMaxStreamsUnidirectional: UInt64 = 0
    /// Our limits on the streams the peer opens, and the counts it opened.
    var localMaxStreamsBidirectional: UInt64
    var localMaxStreamsUnidirectional: UInt64
    private(set) var remoteOpenedBidirectional: UInt64 = 0
    private(set) var remoteOpenedUnidirectional: UInt64 = 0
    private var remoteClosedBidirectional: UInt64 = 0
    private var remoteClosedUnidirectional: UInt64 = 0
    var maxStreamsBidirectionalPending = false
    var maxStreamsUnidirectionalPending = false
    private let initialLocalMaxStreamsBidirectional: UInt64
    private let initialLocalMaxStreamsUnidirectional: UInt64

    init(isServer: Bool, localMaxStreamsBidirectional: UInt64, localMaxStreamsUnidirectional: UInt64) {
        self.isServer = isServer
        self.nextLocalBidirectional = isServer ? 1 : 0
        self.nextLocalUnidirectional = isServer ? 3 : 2
        self.localMaxStreamsBidirectional = localMaxStreamsBidirectional
        self.localMaxStreamsUnidirectional = localMaxStreamsUnidirectional
        self.initialLocalMaxStreamsBidirectional = localMaxStreamsBidirectional
        self.initialLocalMaxStreamsUnidirectional = localMaxStreamsUnidirectional
    }

    static func isLocal(_ id: UInt64, isServer: Bool) -> Bool {
        (id & 0x1 == 1) == isServer
    }

    static func isBidirectional(_ id: UInt64) -> Bool {
        id & 0x2 == 0
    }

    func isLocal(_ id: UInt64) -> Bool {
        Self.isLocal(id, isServer: self.isServer)
    }

    /// The ID the next locally opened stream of this kind gets, if the peer's limit allows it.
    func nextLocalStreamID(bidirectional: Bool) -> UInt64? {
        if bidirectional {
            return self.nextLocalBidirectional / 4 < self.peerMaxStreamsBidirectional
                ? self.nextLocalBidirectional : nil
        } else {
            return self.nextLocalUnidirectional / 4 < self.peerMaxStreamsUnidirectional
                ? self.nextLocalUnidirectional : nil
        }
    }

    mutating func openLocal(bidirectional: Bool, sendLimit: UInt64, receiveWindow: UInt64) -> UInt64? {
        guard let id = self.nextLocalStreamID(bidirectional: bidirectional) else { return nil }
        if bidirectional {
            self.nextLocalBidirectional &+= 4
        } else {
            self.nextLocalUnidirectional &+= 4
        }
        self.streams[id] = CoreStream(
            id: id,
            canSend: true,
            canReceive: bidirectional,
            sendLimit: sendLimit,
            receiveWindow: bidirectional ? receiveWindow : 0
        )
        return id
    }

    enum RemoteStreamError: Error {
        case streamLimit
        case streamState
    }

    /// Opens every peer-initiated stream up to `id`. Returns the newly opened IDs.
    mutating func openRemote(
        upTo id: UInt64,
        sendLimit: (Bool) -> UInt64,
        receiveWindow: (Bool) -> UInt64
    ) throws(RemoteStreamError) -> [UInt64] {
        let bidirectional = Self.isBidirectional(id)
        let index = id / 4
        let opened = bidirectional ? self.remoteOpenedBidirectional : self.remoteOpenedUnidirectional
        guard index >= opened else { return [] }
        let limit = bidirectional ? self.localMaxStreamsBidirectional : self.localMaxStreamsUnidirectional
        guard index < limit else { throw .streamLimit }
        var newIDs: [UInt64] = []
        let base = id & 0x3
        for streamIndex in opened...index {
            let newID = streamIndex * 4 + base
            self.streams[newID] = CoreStream(
                id: newID,
                canSend: bidirectional,
                canReceive: true,
                sendLimit: bidirectional ? sendLimit(true) : 0,
                receiveWindow: receiveWindow(bidirectional)
            )
            newIDs.append(newID)
        }
        if bidirectional {
            self.remoteOpenedBidirectional = index &+ 1
        } else {
            self.remoteOpenedUnidirectional = index &+ 1
        }
        return newIDs
    }

    /// Whether `id` names a stream that existed and is now gone.
    func wasClosed(_ id: UInt64) -> Bool {
        guard self.streams[id] == nil else { return false }
        let index = id / 4
        if self.isLocal(id) {
            let next = Self.isBidirectional(id) ? self.nextLocalBidirectional : self.nextLocalUnidirectional
            return id < next
        }
        return index < (Self.isBidirectional(id) ? self.remoteOpenedBidirectional : self.remoteOpenedUnidirectional)
    }

    /// Whether a frame for local stream `id` refers to a stream we never opened.
    func isUnopenedLocal(_ id: UInt64) -> Bool {
        guard self.isLocal(id) else { return false }
        let next = Self.isBidirectional(id) ? self.nextLocalBidirectional : self.nextLocalUnidirectional
        return id >= next
    }

    mutating func enqueueForSending(_ id: UInt64) {
        if self.queued.insert(id).inserted {
            self.sendQueue.append(id)
        }
    }

    mutating func popSendQueue() -> UInt64? {
        guard let id = self.sendQueue.popFirst() else { return nil }
        self.queued.remove(id)
        return id
    }

    mutating func pushFrontSendQueue(_ id: UInt64) {
        if self.queued.insert(id).inserted {
            self.sendQueue.prepend(id)
        }
    }

    /// Forgets a closed stream, and raises the peer's stream limit when a peer stream goes away.
    mutating func remove(_ id: UInt64) {
        guard self.streams.removeValue(forKey: id) != nil else { return }
        if !self.isLocal(id) {
            if Self.isBidirectional(id) {
                self.remoteClosedBidirectional &+= 1
                self.localMaxStreamsBidirectional =
                    self.remoteClosedBidirectional &+ self.initialLocalMaxStreamsBidirectional
                self.maxStreamsBidirectionalPending = true
            } else {
                self.remoteClosedUnidirectional &+= 1
                self.localMaxStreamsUnidirectional =
                    self.remoteClosedUnidirectional &+ self.initialLocalMaxStreamsUnidirectional
                self.maxStreamsUnidirectionalPending = true
            }
        }
    }
}

#endif
