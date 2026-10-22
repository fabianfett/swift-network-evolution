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

/// One QUIC connection as a state machine.
///
/// It performs no I/O and schedules nothing. The owner feeds it datagrams and timeouts, pulls the
/// datagrams it wants to send with ``send(into:now:)``, arms one timer for ``nextDeadline``, and
/// acts on the events from ``nextEvent()``.
@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public struct QUICConnectionCore: ~Copyable {
    public struct Configuration {
        public var tlsOptions: SwiftTLSProtocol.Options
        public var initialMaxData: UInt64 = 1 << 20
        public var initialMaxStreamDataBidirectionalLocal: UInt64 = 256 * 1024
        public var initialMaxStreamDataBidirectionalRemote: UInt64 = 256 * 1024
        public var initialMaxStreamDataUnidirectional: UInt64 = 256 * 1024
        public var initialMaxStreamsBidirectional: UInt64 = 100
        public var initialMaxStreamsUnidirectional: UInt64 = 100
        public var maxIdleTimeout: NetworkDuration = .seconds(30)
        /// The largest UDP payload this endpoint sends.
        public var maxDatagramSize: Int = 1350
        public var maxDatagramFrameSize: UInt64?
        public var activeConnectionIDLimit: UInt64 = 2

        public init(tlsOptions: SwiftTLSProtocol.Options) {
            self.tlsOptions = tlsOptions
        }
    }

    public enum Event: Equatable {
        /// The handshake completed.
        case connected
        /// The peer opened a stream.
        case streamOpened(UInt64)
        /// A stream has bytes, or its end, to read.
        case streamReadable(UInt64)
        /// A stream that was out of send capacity can be written again.
        case streamWritable(UInt64)
        /// The peer reset a stream.
        case streamReset(UInt64, errorCode: UInt64)
        /// The peer asked us to stop sending on a stream.
        case stopSending(UInt64, errorCode: UInt64)
        /// The peer acknowledged all data and the FIN of a stream.
        case streamFinishedSending(UInt64)
        /// Both directions of a stream are done and the stream is gone.
        case streamClosed(UInt64)
        /// The connection is closed and can be released.
        case closed(CloseReason)
    }

    public enum CloseReason: Equatable {
        /// We closed the connection.
        case local(errorCode: UInt64, isApplication: Bool)
        /// The peer closed the connection.
        case peer(errorCode: UInt64, isApplication: Bool, reason: String)
        /// The connection was idle for too long.
        case idleTimeout
        /// The connection failed: a protocol violation or a TLS failure.
        case transportError(errorCode: UInt64, reason: String)
    }

    enum State {
        case handshaking
        case established
        /// We sent CONNECTION_CLOSE and wait out 3 PTO.
        case closing(until: NetworkClock.Instant)
        /// The peer sent CONNECTION_CLOSE; we wait out 3 PTO without sending.
        case draining(until: NetworkClock.Instant)
        case closed
    }

    struct PendingClose {
        var errorCode: UInt64
        var isApplication: Bool
        var frameType: UInt64
        var reason: String
    }

    let isServer: Bool
    var configuration: Configuration
    var log: LogPrefixer

    public internal(set) var localConnectionID: QUICConnectionID
    public internal(set) var peerConnectionID: QUICConnectionID
    let originalDestinationConnectionID: QUICConnectionID
    var initialToken: [UInt8] = []
    var receivedFirstServerPacket = false

    var protector: Protector
    var parser: PacketParser
    var handshake: CoreHandshake
    var acks: [CoreAckTracker] = [CoreAckTracker(), CoreAckTracker(), CoreAckTracker()]
    var recovery: CoreRecovery
    var streams: CoreStreamMap

    // Connection flow control.
    var sendMaxData: UInt64 = 0
    var sentData: UInt64 = 0
    var receiveMaxData: UInt64
    var receivedData: UInt64 = 0
    var consumedData: UInt64 = 0
    var maxDataPending = false
    var dataBlockedPending = false

    public internal(set) var peerTransportParameters: TransportParameters?
    var state: State = .handshaking
    public internal(set) var isHandshakeConfirmed = false
    var handshakeDonePending = false
    var spaceDiscarded = [false, false, false]
    var addressValidated: Bool
    var bytesReceived = 0
    var bytesSent = 0
    var idleTimeout: NetworkDuration
    var idleDeadline: NetworkClock.Instant?
    var lastAckElicitingSentTime: NetworkClock.Instant?
    /// Probe packets to send per space after a PTO.
    var probesPending = [0, 0, 0]
    var pendingClose: PendingClose?
    var closeFrameSentInState = false
    var closeReason: CloseReason?
    var events = Deque<Event>()
    /// PATH_CHALLENGE data to answer with PATH_RESPONSE.
    var pendingPathResponses: [UInt64] = []

    var isClosed: Bool {
        if case .closed = self.state { return true }
        return false
    }

    // Keeps the destruction of the internal state inside this module: a client module that
    // specialized it would reference this module's internal types.
    @inline(never)
    deinit {}

    var isClosingOrDraining: Bool {
        switch self.state {
        case .closing, .draining, .closed: return true
        default: return false
        }
    }

    /// Creates a client connection.
    public init(
        clientWith configuration: Configuration,
        localConnectionID: QUICConnectionID,
        destinationConnectionID: QUICConnectionID,
        now: NetworkClock.Instant
    ) {
        self.init(
            isServer: false,
            configuration: configuration,
            localConnectionID: localConnectionID,
            peerConnectionID: destinationConnectionID,
            originalDestinationConnectionID: destinationConnectionID,
            now: now
        )
    }

    /// Creates a server connection for a client's first Initial packet.
    ///
    /// - Parameters:
    ///   - originalDestinationConnectionID: The destination connection ID of the client's Initial.
    ///   - peerConnectionID: The source connection ID of the client's Initial.
    public init(
        serverWith configuration: Configuration,
        localConnectionID: QUICConnectionID,
        originalDestinationConnectionID: QUICConnectionID,
        peerConnectionID: QUICConnectionID,
        now: NetworkClock.Instant
    ) {
        self.init(
            isServer: true,
            configuration: configuration,
            localConnectionID: localConnectionID,
            peerConnectionID: peerConnectionID,
            originalDestinationConnectionID: originalDestinationConnectionID,
            now: now
        )
    }

    private init(
        isServer: Bool,
        configuration: Configuration,
        localConnectionID: QUICConnectionID,
        peerConnectionID: QUICConnectionID,
        originalDestinationConnectionID: QUICConnectionID,
        now: NetworkClock.Instant
    ) {
        self.isServer = isServer
        self.configuration = configuration
        self.log = LogPrefixer(isServer ? "[QSM-S]" : "[QSM-C]")
        self.localConnectionID = localConnectionID
        self.peerConnectionID = peerConnectionID
        self.originalDestinationConnectionID = originalDestinationConnectionID
        self.protector = Protector(
            isClient: !isServer,
            destinationCID: originalDestinationConnectionID,
            logPrefixer: self.log
        )
        self.parser = PacketParser(logPrefixer: self.log)
        self.handshake = CoreHandshake(isServer: isServer)
        self.recovery = CoreRecovery()
        self.streams = CoreStreamMap(
            isServer: isServer,
            localMaxStreamsBidirectional: configuration.initialMaxStreamsBidirectional,
            localMaxStreamsUnidirectional: configuration.initialMaxStreamsUnidirectional
        )
        self.receiveMaxData = configuration.initialMaxData
        self.addressValidated = !isServer
        self.idleTimeout = configuration.maxIdleTimeout
        self.idleDeadline = now.advanced(by: configuration.maxIdleTimeout)

        var tlsOptions = configuration.tlsOptions
        tlsOptions.quicTransportParameters = self.localTransportParameters()
        var outputs: [CoreHandshake.Output] = []
        self.handshake.start(tlsOptions: tlsOptions, outputs: &outputs)
        self.apply(outputs, now: now)
    }

    private func localTransportParameters() -> [UInt8] {
        var parameters = TransportParameters(logPrefixer: self.log)
        if self.isServer {
            parameters.append(.originalDCID(connectionID: self.originalDestinationConnectionID))
        }
        parameters.append(.initialSCID(connectionID: self.localConnectionID))
        parameters.append(.maxIdleTimeout(value: UInt64(self.configuration.maxIdleTimeout.milliseconds)))
        parameters.append(.maxUDPPayloadSize(value: 65527))
        parameters.append(.initialMaxData(value: self.configuration.initialMaxData))
        parameters.append(
            .initialMaxStreamDataBidirectionalLocal(value: self.configuration.initialMaxStreamDataBidirectionalLocal)
        )
        parameters.append(
            .initialMaxStreamDataBidirectionalRemote(value: self.configuration.initialMaxStreamDataBidirectionalRemote)
        )
        parameters.append(
            .initialMaxStreamDataUnidirectional(value: self.configuration.initialMaxStreamDataUnidirectional)
        )
        parameters.append(.initialMaxStreamsBidirectional(value: self.configuration.initialMaxStreamsBidirectional))
        parameters.append(.initialMaxStreamsUnidirectional(value: self.configuration.initialMaxStreamsUnidirectional))
        parameters.append(.activeConnectionIDLimit(value: self.configuration.activeConnectionIDLimit))
        if let maxDatagramFrameSize = self.configuration.maxDatagramFrameSize {
            parameters.append(.maxDatagramFrameSize(value: maxDatagramFrameSize))
        }
        return (try? parameters.serialize()) ?? []
    }

    // MARK: Events and timers

    /// The next event to act on, if any.
    public mutating func nextEvent() -> Event? {
        self.events.popFirst()
    }

    /// When ``handleTimeout(now:)`` has to be called next.
    public var nextDeadline: NetworkClock.Instant? {
        var deadline: NetworkClock.Instant?
        func consider(_ candidate: NetworkClock.Instant?) {
            guard let candidate else { return }
            if deadline == nil || candidate < deadline! {
                deadline = candidate
            }
        }
        switch self.state {
        case .closed:
            return nil
        case .closing(let until), .draining(let until):
            return until
        case .handshaking, .established:
            break
        }
        consider(self.idleDeadline)
        consider(self.lossDetectionDeadline?.deadline)
        for space in PacketNumberSpace.allCases where !self.spaceDiscarded[Int(space.rawValue)] {
            consider(self.acks[space].ackDeadline)
        }
        return deadline
    }

    var lossDetectionDeadline: (deadline: NetworkClock.Instant, space: PacketNumberSpace)? {
        self.recovery.lossDetectionDeadline(
            handshakeConfirmed: self.isHandshakeConfirmed,
            hasHandshakeKeys: self.protector.sealKeyReady(for: .handshake),
            peerAwaitingAddressValidation: self.peerAwaitingAddressValidation
        )
    }

    /// A client keeps probing until it knows the server validated its address.
    var peerAwaitingAddressValidation: Bool {
        !self.isServer && !self.isHandshakeConfirmed && !self.receivedHandshakeAck
    }

    var receivedHandshakeAck: Bool {
        self.recovery.spaces[Int(PacketNumberSpace.handshake.rawValue)].largestAcknowledged != nil
    }

    public mutating func handleTimeout(now: NetworkClock.Instant) {
        switch self.state {
        case .closed:
            return
        case .closing(let until), .draining(let until):
            if now >= until {
                self.enterClosed()
            }
            return
        case .handshaking, .established:
            break
        }
        if let idleDeadline = self.idleDeadline, now >= idleDeadline {
            self.closeReason = .idleTimeout
            self.enterClosed()
            return
        }
        for space in PacketNumberSpace.allCases {
            if let ackDeadline = self.acks[space].ackDeadline, now >= ackDeadline {
                self.acks[space].ackNeeded = true
                self.acks[space].ackDeadline = nil
            }
        }
        if let (deadline, _) = self.lossDetectionDeadline, now >= deadline {
            let timeout = self.recovery.onLossDetectionTimeout(
                handshakeConfirmed: self.isHandshakeConfirmed,
                hasHandshakeKeys: self.protector.sealKeyReady(for: .handshake),
                peerAwaitingAddressValidation: self.peerAwaitingAddressValidation,
                now: now
            )
            switch timeout {
            case .lost(let lost, let space):
                for packet in lost {
                    self.onPacketLost(packet, in: space)
                }
            case .probe(let space):
                self.probesPending[Int(space.rawValue)] = 2
                // Probe in every other space with keys and data in flight too (RFC 9002 Section
                // 6.2.4): the peer may already have dropped the keys of the space whose timer fired.
                // That includes 1-RTT before the handshake is confirmed, whose own timer isn't armed
                // yet but which a server that completed its handshake can acknowledge.
                if !self.isHandshakeConfirmed && space != .applicationData {
                    self.requeueUnacknowledgedCrypto(in: space)
                    for other in PacketNumberSpace.allCases where other != space {
                        let index = Int(other.rawValue)
                        guard !self.spaceDiscarded[index], self.recovery.spaces[index].ackElicitingInFlight > 0 else {
                            continue
                        }
                        if other == .applicationData && !self.handshake.isComplete {
                            continue
                        }
                        self.probesPending[index] = max(self.probesPending[index], 1)
                        if other != .applicationData {
                            self.requeueUnacknowledgedCrypto(in: other)
                        }
                    }
                }
            case .none:
                break
            }
        }
    }

    // MARK: Closing

    /// Closes the connection, sending CONNECTION_CLOSE.
    public mutating func close(errorCode: UInt64, isApplication: Bool, reason: String = "", now: NetworkClock.Instant) {
        guard !self.isClosingOrDraining else { return }
        self.closeReason = .local(errorCode: errorCode, isApplication: isApplication)
        guard self.bytesSent > 0 else {
            // Nothing was ever sent, so there is no peer state to close.
            self.enterClosed()
            return
        }
        self.startClosing(
            PendingClose(errorCode: errorCode, isApplication: isApplication, frameType: 0, reason: reason),
            now: now
        )
    }

    mutating func closeWithError(_ errorCode: UInt64, frameType: UInt64 = 0, reason: String, now: NetworkClock.Instant)
    {
        guard !self.isClosingOrDraining else { return }
        self.log.error("Closing with transport error \(errorCode): \(reason)")
        self.closeReason = .transportError(errorCode: errorCode, reason: reason)
        self.startClosing(
            PendingClose(errorCode: errorCode, isApplication: false, frameType: frameType, reason: reason),
            now: now
        )
    }

    private mutating func startClosing(_ close: PendingClose, now: NetworkClock.Instant) {
        self.pendingClose = close
        self.closeFrameSentInState = false
        let pto = self.recovery.probeTimeout(includingMaxAckDelay: true)
        self.state = .closing(until: now.advanced(by: pto * 3))
    }

    private mutating func enterDraining(now: NetworkClock.Instant) {
        let pto = self.recovery.probeTimeout(includingMaxAckDelay: true)
        self.state = .draining(until: now.advanced(by: pto * 3))
    }

    private mutating func enterClosed() {
        guard !self.isClosed else { return }
        self.state = .closed
        self.handshake.release()
        self.events.append(.closed(self.closeReason ?? .idleTimeout))
    }

    // MARK: Streams

    /// Opens a stream, if the peer's stream limit allows it.
    public mutating func openStream(bidirectional: Bool) -> UInt64? {
        guard !self.isClosingOrDraining else { return nil }
        let sendLimit: UInt64
        if bidirectional {
            sendLimit = UInt64(self.peerTransportParameters?.intValue(.initialMaxStreamDataBidirectionalRemote) ?? 0)
        } else {
            sendLimit = UInt64(self.peerTransportParameters?.intValue(.initialMaxStreamDataUnidirectional) ?? 0)
        }
        return self.streams.openLocal(
            bidirectional: bidirectional,
            sendLimit: sendLimit,
            receiveWindow: self.configuration.initialMaxStreamDataBidirectionalLocal
        )
    }

    /// The bytes the application may enqueue on `stream` without exceeding the peer's limits.
    public func writableBytes(on stream: UInt64) -> Int {
        guard let stream = self.streams.streams[stream] else { return 0 }
        return stream.sendCapacity
    }

    /// Enqueues bytes on a stream. Returns how many bytes were accepted.
    ///
    /// All bytes are buffered; flow control applies when they are sent. Writing past
    /// ``writableBytes(on:)`` makes the stream report ``Event/streamWritable(_:)`` once the peer
    /// raises its limit.
    @discardableResult
    public mutating func write(_ bytes: RawSpan, to streamID: UInt64, fin: Bool = false) -> Int {
        guard !self.isClosingOrDraining, var stream = self.streams.streams.removeValue(forKey: streamID) else {
            return 0
        }
        defer { self.streams.streams[streamID] = stream }
        guard stream.canSend, stream.resetCode == nil, !stream.send.isFinished else {
            return 0
        }
        if bytes.byteCount > 0 {
            stream.send.append(bytes)
        }
        if stream.send.writeOffset >= stream.sendLimit {
            stream.writableBlocked = true
        }
        if fin {
            stream.send.finish()
        }
        if stream.hasPendingFrames {
            self.streams.enqueueForSending(streamID)
        }
        return bytes.byteCount
    }

    /// Finishes the send side of a stream.
    public mutating func finish(_ streamID: UInt64) {
        guard var stream = self.streams.streams[streamID], stream.canSend, stream.resetCode == nil else { return }
        stream.send.finish()
        self.streams.streams[streamID] = stream
        self.streams.enqueueForSending(streamID)
    }

    /// Calls `body` with the readable bytes of a stream; `body` returns how many bytes it consumed.
    ///
    /// Returns `nil` if the stream does not exist.
    public mutating func read<Result>(
        from streamID: UInt64,
        _ body: (RawSpan, _ isFinished: Bool) -> (consumed: Int, result: Result)
    ) -> Result? {
        guard var stream = self.streams.streams.removeValue(forKey: streamID) else { return nil }
        let before = stream.receive.readOffset
        let finalSize = stream.receive.finalSize
        let contiguousEnd = stream.receive.contiguousEnd
        let result = stream.receive.read { bytes in
            body(bytes, finalSize != nil && contiguousEnd == finalSize)
        }
        let consumed = stream.receive.readOffset &- before
        stream.readableReported = false
        if consumed > 0 {
            self.consumedData &+= consumed
            if stream.updateReceiveLimit() {
                self.streams.enqueueForSending(streamID)
            }
            self.updateConnectionReceiveLimit()
        }
        self.storeOrRemove(stream)
        return result
    }

    /// Resets the send side of a stream with RESET_STREAM.
    public mutating func resetStream(_ streamID: UInt64, errorCode: UInt64) {
        guard var stream = self.streams.streams[streamID], stream.canSend, stream.resetCode == nil else { return }
        guard !stream.send.isFullyAcknowledged else { return }
        stream.resetCode = errorCode
        stream.resetPending = true
        self.streams.streams[streamID] = stream
        self.streams.enqueueForSending(streamID)
    }

    /// Asks the peer to stop sending on a stream with STOP_SENDING.
    public mutating func stopSending(_ streamID: UInt64, errorCode: UInt64) {
        guard var stream = self.streams.streams[streamID], stream.canReceive, stream.stopSendingCode == nil else {
            return
        }
        guard stream.peerResetCode == nil, !stream.receive.isComplete else { return }
        stream.stopSendingCode = errorCode
        stream.stopSendingPending = true
        self.consumedData &+= stream.receive.discard()
        self.updateConnectionReceiveLimit()
        self.streams.streams[streamID] = stream
        self.streams.enqueueForSending(streamID)
    }

    mutating func updateConnectionReceiveLimit() {
        let window = self.configuration.initialMaxData
        let target = self.consumedData &+ window
        if target &- self.receiveMaxData >= window / 2 {
            self.receiveMaxData = target
            self.maxDataPending = true
        }
    }

    mutating func storeOrRemove(_ stream: consuming CoreStream) {
        var stream = stream
        let id = stream.id
        if !stream.creditReturned && !self.streams.isLocal(id) && stream.isDoneForStreamCredit {
            stream.creditReturned = true
            self.streams.returnStreamCredit(id)
        }
        if stream.isClosed {
            self.events.append(.streamClosed(id))
            if !stream.creditReturned {
                self.streams.returnStreamCredit(id)
            }
            // The caller may or may not have taken the stream out of the map.
            self.streams.streams[id] = nil
        } else {
            self.streams.streams[id] = stream
        }
    }
}

// MARK: - Acknowledgement tracking

/// The received packet numbers of one packet number space, and when to acknowledge them.
@available(Network 0.1.0, *)
struct CoreAckTracker {
    var received = CoreRangeSet()
    /// Packet numbers below this are treated as received; their ACKs were acknowledged.
    var floor: UInt64 = 0
    var largestReceived: UInt64?
    var largestReceivedTime: NetworkClock.Instant = .zero
    var ackElicitingSinceAck = 0
    /// An ACK frame has to go out with the next packet in this space.
    var ackNeeded = false
    var ackDeadline: NetworkClock.Instant?

    static let maximumRanges = 64

    func isDuplicate(_ packetNumber: UInt64) -> Bool {
        packetNumber < self.floor || self.received.contains(packetNumber)
    }

    mutating func onPacketReceived(
        _ packetNumber: UInt64,
        isAckEliciting: Bool,
        immediate: Bool,
        maxAckDelay: NetworkDuration,
        now: NetworkClock.Instant
    ) {
        let outOfOrder = self.largestReceived.map { packetNumber < $0 || packetNumber > $0 &+ 1 } ?? false
        self.received.insert(packetNumber)
        self.received.trim(toCount: Self.maximumRanges)
        if self.largestReceived == nil || packetNumber > self.largestReceived! {
            self.largestReceived = packetNumber
            self.largestReceivedTime = now
        }
        guard isAckEliciting else { return }
        self.ackElicitingSinceAck &+= 1
        if immediate || outOfOrder || self.ackElicitingSinceAck >= 2 {
            self.ackNeeded = true
            self.ackDeadline = nil
        } else if self.ackDeadline == nil {
            self.ackDeadline = now.advanced(by: maxAckDelay)
        }
    }

    var hasAckToSend: Bool {
        !self.received.isEmpty
    }

    /// Writes an ACK frame for everything received. Returns the largest acknowledged packet number.
    func writeAck(into writer: inout CoreWriter, now: NetworkClock.Instant, ackDelayExponent: Int) -> UInt64? {
        guard let largest = self.largestReceived, !self.received.isEmpty else { return nil }
        let ranges = self.received.ranges
        var delay = UInt64(max(0, self.largestReceivedTime.duration(to: now).microseconds))
        delay >>= UInt64(ackDelayExponent)
        let start = writer.offset
        var ok = writer.vle(0x02) && writer.vle(largest) && writer.vle(delay)
        ok = ok && writer.vle(UInt64(ranges.count &- 1))
        // Ranges are ascending; ACK frames list them descending.
        var index = ranges.count &- 1
        var previousLower = ranges[index].lowerBound
        ok = ok && writer.vle(ranges[index].upperBound &- 1 &- ranges[index].lowerBound)
        index &-= 1
        while ok && index >= 0 {
            let range = ranges[index]
            let gap = previousLower &- range.upperBound &- 1
            ok = writer.vle(gap) && writer.vle(range.upperBound &- 1 &- range.lowerBound)
            previousLower = range.lowerBound
            index &-= 1
        }
        guard ok else {
            _ = start
            return nil
        }
        return largest
    }

    func ackFrameLength(now: NetworkClock.Instant, ackDelayExponent: Int) -> Int {
        guard let largest = self.largestReceived, !self.received.isEmpty else { return 0 }
        let ranges = self.received.ranges
        var length = 1 + CoreWriter.vleLength(largest) + 8 + CoreWriter.vleLength(UInt64(ranges.count))
        for range in ranges {
            length &+= 2 * CoreWriter.vleLength(range.upperBound &- range.lowerBound)
        }
        return length
    }

    mutating func onAckSent() {
        self.ackNeeded = false
        self.ackDeadline = nil
        self.ackElicitingSinceAck = 0
    }

    /// Called when a packet carrying our ACK frame with `largest` was acknowledged.
    mutating func onAckAcknowledged(largest: UInt64) {
        // Older packet numbers no longer need acknowledging.
        if largest &+ 1 > self.floor {
            self.floor = largest &+ 1
            self.received.removeAll(below: self.floor)
        }
    }
}

@available(Network 0.1.0, *)
extension Array where Element == CoreAckTracker {
    subscript(space: PacketNumberSpace) -> CoreAckTracker {
        get { self[Int(space.rawValue)] }
        _modify { yield &self[Int(space.rawValue)] }
    }
}

#endif

// MARK: - Handshake state for drivers

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// Whether the TLS handshake completed.
    public var isHandshakeComplete: Bool {
        self.handshake.isComplete
    }

    /// Whether the connection is closing, draining or closed.
    public var isTerminating: Bool {
        self.isClosingOrDraining
    }

    /// The peer's `max_datagram_frame_size`, or `0` if it does not accept datagrams.
    public var peerMaxDatagramFrameSize: Int {
        self.peerTransportParameters?.intValue(.maxDatagramFrameSize) ?? 0
    }

    /// The peer's `active_connection_id_limit`.
    public var peerActiveConnectionIDLimit: Int {
        self.peerTransportParameters?.intValue(.activeConnectionIDLimit) ?? 2
    }

    /// Whether a stream exists.
    public func hasStream(_ streamID: UInt64) -> Bool {
        self.streams.streams[streamID] != nil
    }
}
