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
        /// Zero disables the idle timeout on our side (RFC 9000 Section 10.1).
        public var maxIdleTimeout: NetworkDuration = .seconds(30)
        /// Sends a PING once nothing arrived for this long, to keep the connection and the path
        /// alive; `nil` sends none. An interval at or above the idle timeout has no effect.
        public var keepAliveInterval: NetworkDuration?
        /// Closes the connection once this many keepalives in a row went unacknowledged; zero
        /// never does.
        public var maxUnacknowledgedKeepAlives = 0
        /// The largest UDP payload this endpoint sends, until PMTUD finds that a path carries more.
        public var maxDatagramSize: Int = 1350
        /// Whether this endpoint probes for larger datagrams once the handshake is confirmed
        /// (RFC 9000 Section 14.3).
        public var pmtudEnabled = false
        /// Whether PMTUD probes as soon as the congestion window allows, even when the data to
        /// send doesn't make up for the probe.
        public var pmtudIgnoreCost = false
        /// How long after a search ended PMTUD tries larger datagrams again.
        public var pmtudInterval: NetworkDuration = .seconds(600)
        /// The MTU of the interface, which caps PMTUD; zero if unknown, which allows 1280 bytes.
        /// ``setInterfaceMTU(_:on:)`` sets it per path.
        public var interfaceMTU = 0
        /// The size of the IP and UDP headers of a datagram: 28 for IPv4, 48 for IPv6.
        public var ipUDPHeaderSize = 48
        /// The size a client pads the datagrams of its Initial packets to, at least 1200 bytes
        /// (RFC 9000 Section 14.1).
        public var initialDatagramSize: Int = 1200
        /// The largest DATAGRAM frame (RFC 9221) this endpoint accepts, including its type and
        /// length; `nil` refuses them.
        public var maxDatagramFrameSize: UInt64?
        public var activeConnectionIDLimit: UInt64 = 2
        /// Whether the core issues connection IDs of its own after the handshake, up to
        /// `maxIssuedConnectionIDs` and the peer's limit. Otherwise ``issueConnectionID(_:statelessResetToken:)``
        /// does, and the driver routes them.
        public var automaticallyIssueConnectionIDs = false
        public var maxIssuedConnectionIDs = 8
        /// The stateless reset token a server sends for the connection ID of its handshake.
        public var statelessResetToken: QUICStatelessResetToken?
        /// Tells the peer not to migrate, as a server whose connection IDs are empty has to.
        public var disableActiveMigration = false
        /// The `max_udp_payload_size` transport parameter.
        public var maxUDPPayloadSize: UInt64 = 65527
        /// Whether this endpoint spins the latency spin bit (RFC 9000 Section 17.4). When it
        /// doesn't, every short header carries `spinValue`.
        public var spinBitEnabled = false
        public var spinValue = false
        /// The version of a client's Initial packets until the server answers with Version
        /// Negotiation. Only tests use anything but QUIC version 1.
        public var clientInitialVersion: UInt32 = QUICVersion.v1.rawValue
        /// How long this endpoint delays acknowledgements, sent as `max_ack_delay` unless it is
        /// the default 25 ms.
        public var maxAckDelay: NetworkDuration = .milliseconds(25)
        /// Whether a client sends the data of its 0-RTT packets again when the server rejects
        /// them. Otherwise its streams start over empty, and ``Event/earlyDataRejected`` tells
        /// the application to write again.
        public var resendRejectedEarlyData = false
        /// Whether the connection paces what it sends once the handshake completed: each
        /// datagram gets a ``QUICConnectionCore/departureTime`` for the kernel (RFC 9002 Section
        /// 7.7).
        public var pacingEnabled = false
        /// Whether the connection records ``PacketEvent``s, for qlog.
        public var recordsPacketEvents = false
        /// Whether this endpoint sends ECN-capable packets once it validated that the path
        /// carries them (RFC 9000 Section 13.4.2). The driver sets ``lastDatagramECN`` in the IP
        /// header of each datagram.
        public var ecnEnabled = false
        /// Whether this endpoint reports the ECN codepoints of the packets it receives in its
        /// ACK frames (RFC 9000 Section 13.4.1). The driver passes them to
        /// ``receive(_:on:ecn:now:)``.
        public var ecnEchoEnabled = true
        /// Whether ECN-capable packets carry ECT(1), as L4S does, instead of ECT(0).
        public var useECT1 = false
        /// The congestion controller. Prague always paces.
        public var congestionControl = CoreCongestionControlAlgorithm.cubic

        #if DEBUG
        /// Changes the transport parameters this endpoint sends, so tests can send what a broken
        /// peer would.
        var transportParametersForTesting: ((inout TransportParameters) -> Void)?
        #endif

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
        /// DATAGRAM frames arrived; read them with ``readDatagram(_:)``.
        case datagramsReadable
        /// This endpoint issued a connection ID; packets to it belong to the connection.
        case newLocalConnectionID(
            sequenceNumber: UInt64,
            QUICConnectionID,
            statelessResetToken: QUICStatelessResetToken
        )
        /// The peer retired one of this endpoint's connection IDs.
        case retiredLocalConnectionID(QUICConnectionID)
        /// The peer issued a connection ID this endpoint may send to.
        case newPeerConnectionID(
            sequenceNumber: UInt64,
            QUICConnectionID,
            statelessResetToken: QUICStatelessResetToken
        )
        /// This endpoint retired one of the peer's connection IDs.
        case retiredPeerConnectionID(QUICConnectionID, statelessResetToken: QUICStatelessResetToken?)
        /// A PATH_RESPONSE validated the path.
        case pathValidated(CorePathID)
        /// The path didn't answer PATH_CHALLENGE.
        case pathFailed(CorePathID)
        /// Packets go out on the path now: this endpoint migrated, or the peer did.
        case activePathChanged(CorePathID)
        /// The server rejected this client's 0-RTT packets (RFC 9001 Section 4.6.2).
        case earlyDataRejected
        /// The server's transport parameters, which a client remembers for 0-RTT on a later
        /// connection. Only a client with early data enabled gets them.
        case transportParametersForResumption([UInt8])
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
        /// Too many keepalives in a row went unacknowledged. The connection sent CONNECTION_CLOSE
        /// with NO_ERROR.
        case keepAliveTimeout
        /// The peer lost the connection's state and sent a stateless reset (RFC 9000 Section 10.3).
        case statelessReset
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
    /// The source connection ID of the server's Retry, which its transport parameters repeat.
    public internal(set) var retrySourceConnectionID: QUICConnectionID?
    /// The version of the long headers this endpoint sends.
    var version: UInt32 = QUICVersion.v1.rawValue
    /// Whether a client acted on a Version Negotiation packet; it does so once.
    var receivedVersionNegotiation = false
    /// The token a client's Initial packets carry, from the server's Retry.
    public internal(set) var initialToken: [UInt8] = []
    var receivedFirstServerPacket = false
    var connectionIDs: CoreConnectionIDs
    /// The destination connection ID of the packet whose frames are processed.
    var currentPacketDestination: QUICConnectionID?
    /// The packets decrypted and processed so far.
    var packetsProcessed = 0
    /// The spin bit of the short headers we send.
    var spinValue: Bool
    /// The largest packet number of a short header packet received, which the spin bit follows.
    var largestShortHeaderPacketNumber: UInt64?
    /// What happened on the connection, for the framework's statistics.
    var statistics = Statistics()
    /// When the datagram the last ``send(into:on:now:)`` wrote should leave, if the connection
    /// paces; `nil` when it goes out right away.
    public internal(set) var departureTime: NetworkClock.Instant?
    /// The ECN codepoint for the IP header of the datagram the last ``send(into:on:now:)`` wrote.
    public internal(set) var lastDatagramECN = IPProtocol.ECN.nonECT
    /// The largest UDP payload the active path carries: the configured size, or what PMTUD
    /// found.
    public internal(set) var maxDatagramSize: Int
    /// Packets larger than the base size lost in a row on the active path.
    var pmtudLargePacketsLost = 0
    /// The ECN validation of the active path.
    var ecn: CoreECNValidator
    /// The ECN codepoint of the datagram being processed.
    var receivingECN = IPProtocol.ECN.nonECT
    /// Packets sent, received and lost, oldest first, if the configuration records them.
    var packetEvents = Deque<PacketEvent>()
    /// The frame types of the packet being processed, while packet events are recorded.
    var receivedFrameTypes: [PacketEvent.FrameType] = []

    var protector: Protector
    var parser: PacketParser
    /// The key phase of the 1-RTT packets we send (RFC 9001 Section 6).
    var keyPhase: PacketKeyState = .phase0
    /// The lowest packet number received in `keyPhase`. A packet in the other phase with a higher
    /// number is the peer's key update; one with a lower number was sent before the last update.
    /// (The two can't be equal: a packet number is used once per space.)
    /// `nil` after our own update until the peer follows it; zero before any 1-RTT packet, so
    /// that a peer updating right away is followed.
    var keyPhaseFirstReceived: UInt64? = 0
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
    /// The effective idle timeout, the smaller of the two endpoints' nonzero values; `nil` when
    /// both disabled it.
    var idleTimeout: NetworkDuration?
    var idleDeadline: NetworkClock.Instant?
    /// Whether an ack-eliciting packet went out since the last packet arrived.
    var sentAckElicitingSinceReceive = false
    var keepAliveInterval: NetworkDuration?
    /// When the next keepalive goes out, unless a packet arrives first.
    var keepAliveDeadline: NetworkClock.Instant?
    var keepAlivePending = false
    var unacknowledgedKeepAlives = 0
    /// Probe packets to send per space after a PTO.
    var probesPending = [0, 0, 0]
    var pendingClose: PendingClose?
    var closeFrameSentInState = false
    /// The spaces whose CONNECTION_CLOSE didn't go out yet, oldest first.
    var closeSpacesToSend: [PacketNumberSpace] = []
    /// Why the connection is closing, draining or closed; `nil` while it is open.
    public internal(set) var closeReason: CloseReason?
    var events = Deque<Event>()
    /// The network paths, by the driver's ID.
    var paths: [CorePathID: CorePath] = [.initial: CorePath(id: .initial, isValidated: true)]
    var activePath = CorePathID.initial
    /// The path of the datagram being processed.
    var receivingPath = CorePathID.initial
    var largestNonProbingPacketNumber: UInt64?
    /// Whether the packet being processed carried only probing frames (RFC 9000 Section 9.1).
    var packetIsProbing = false
    /// A PING is due, so the peer sees a non-probing packet on a new path.
    var pingPending = false
    var earlyData = CoreEarlyDataState.none
    /// The transport parameters a client sent its 0-RTT packets with.
    var rememberedTransportParameters: TransportParameters?
    /// Whether the peer's transport parameters of this connection arrived, rather than the ones
    /// remembered for 0-RTT.
    var receivedPeerTransportParameters = false
    /// Whether the packet being processed is a 0-RTT packet.
    var packetIsEarlyData = false
    /// DATAGRAM payloads to send, oldest first. They are never retransmitted.
    var datagramsToSend = Deque<[UInt8]>()
    /// DATAGRAM payloads received and not read yet.
    var datagramsReceived = Deque<[UInt8]>()
    /// Queued datagrams beyond this drop the oldest, on either side.
    static let maximumQueuedDatagrams = 1024
    #if DEBUG
    /// Raw frames written into the next 1-RTT packets, ack-eliciting and never retransmitted. Tests
    /// use them to send what a misbehaving peer would.
    var injectedFrames: [[UInt8]] = []
    #endif

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
    ///   - originalDestinationConnectionID: The destination connection ID of the client's first
    ///     Initial, before any Retry.
    ///   - peerConnectionID: The source connection ID of the client's Initial.
    ///   - retrySourceConnectionID: The source connection ID of the Retry this server sent, which
    ///     the client's Initial is addressed to; `nil` without a Retry.
    public init(
        serverWith configuration: Configuration,
        localConnectionID: QUICConnectionID,
        originalDestinationConnectionID: QUICConnectionID,
        peerConnectionID: QUICConnectionID,
        retrySourceConnectionID: QUICConnectionID? = nil,
        now: NetworkClock.Instant
    ) {
        self.init(
            isServer: true,
            configuration: configuration,
            localConnectionID: localConnectionID,
            peerConnectionID: peerConnectionID,
            originalDestinationConnectionID: originalDestinationConnectionID,
            retrySourceConnectionID: retrySourceConnectionID,
            now: now
        )
    }

    private init(
        isServer: Bool,
        configuration: Configuration,
        localConnectionID: QUICConnectionID,
        peerConnectionID: QUICConnectionID,
        originalDestinationConnectionID: QUICConnectionID,
        retrySourceConnectionID: QUICConnectionID? = nil,
        now: NetworkClock.Instant
    ) {
        self.isServer = isServer
        self.configuration = configuration
        self.log = LogPrefixer(isServer ? "[QSM-S]" : "[QSM-C]")
        self.localConnectionID = localConnectionID
        self.peerConnectionID = peerConnectionID
        self.originalDestinationConnectionID = originalDestinationConnectionID
        self.retrySourceConnectionID = retrySourceConnectionID
        self.connectionIDs = CoreConnectionIDs(
            local: localConnectionID,
            localToken: isServer ? configuration.statelessResetToken : nil,
            peer: peerConnectionID
        )
        if !isServer {
            self.version = configuration.clientInitialVersion
        }
        // After a Retry, the client's Initial is addressed to the Retry's connection ID, which
        // the Initial keys come from.
        self.protector = Protector(
            isClient: !isServer,
            destinationCID: retrySourceConnectionID ?? originalDestinationConnectionID,
            logPrefixer: self.log
        )
        self.parser = PacketParser(logPrefixer: self.log)
        self.handshake = CoreHandshake(isServer: isServer)
        self.maxDatagramSize = configuration.maxDatagramSize
        if configuration.congestionControl == .prague {
            // Prague's short bursts need pacing.
            self.configuration.pacingEnabled = true
        }
        self.recovery = CoreRecovery(
            maxDatagramSize: configuration.maxDatagramSize,
            pacingEnabled: self.configuration.pacingEnabled,
            congestionControl: configuration.congestionControl
        )
        self.ecn = CoreECNValidator(markingEnabled: configuration.ecnEnabled, useECT1: configuration.useECT1)
        self.streams = CoreStreamMap(
            isServer: isServer,
            localMaxStreamsBidirectional: configuration.initialMaxStreamsBidirectional,
            localMaxStreamsUnidirectional: configuration.initialMaxStreamsUnidirectional
        )
        self.receiveMaxData = configuration.initialMaxData
        self.addressValidated = !isServer
        self.idleTimeout = configuration.maxIdleTimeout > .zero ? configuration.maxIdleTimeout : nil
        self.keepAliveInterval = configuration.keepAliveInterval
        self.spinValue = configuration.spinValue
        self.idleDeadline = self.idleTimeout.map { now.advanced(by: $0) }

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
            if let retrySourceConnectionID = self.retrySourceConnectionID {
                parameters.append(.retrySCID(connectionID: retrySourceConnectionID))
            }
        }
        parameters.append(.initialSCID(connectionID: self.localConnectionID))
        parameters.append(.maxIdleTimeout(value: UInt64(self.configuration.maxIdleTimeout.milliseconds)))
        parameters.append(.maxUDPPayloadSize(value: self.configuration.maxUDPPayloadSize))
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
        if self.configuration.maxAckDelay != .milliseconds(25) {
            parameters.append(.maxAckDelay(duration: self.configuration.maxAckDelay))
        }
        if self.isServer, let statelessResetToken = self.configuration.statelessResetToken {
            parameters.append(.statelessResetToken(statelessResetToken: statelessResetToken))
        }
        if self.configuration.disableActiveMigration {
            parameters.append(.disableActiveMigration())
        }
        if let maxDatagramFrameSize = self.configuration.maxDatagramFrameSize {
            parameters.append(.maxDatagramFrameSize(value: maxDatagramFrameSize))
        }
        #if DEBUG
        self.configuration.transportParametersForTesting?(&parameters)
        #endif
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
        consider(self.keepAliveDeadline)
        consider(self.nextPathDeadline)
        consider(self.pmtudDeadline)
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
        if let keepAliveDeadline = self.keepAliveDeadline, now >= keepAliveDeadline {
            self.keepAliveTimerFired(now: now)
            if self.isClosingOrDraining { return }
        }
        self.handlePathTimeouts(now: now)
        self.handlePMTUDTimeout(now: now)
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
                    self.onPacketLost(packet, in: space, now: now)
                }
            case .probe(let space):
                self.probesPending[Int(space.rawValue)] = 2
                self.statistics.increment(.probeTimeOuts)
                self.checkPMTUDBlackhole()
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

    mutating func startClosing(_ close: PendingClose, now: NetworkClock.Instant) {
        self.pendingClose = close
        self.closeFrameSentInState = false
        let pto = self.recovery.probeTimeout(includingMaxAckDelay: true)
        self.state = .closing(until: now.advanced(by: pto * 3))
    }

    private mutating func enterDraining(now: NetworkClock.Instant) {
        let pto = self.recovery.probeTimeout(includingMaxAckDelay: true)
        self.state = .draining(until: now.advanced(by: pto * 3))
    }

    mutating func enterClosed() {
        guard !self.isClosed else { return }
        self.state = .closed
        self.handshake.release()
        self.events.append(.closed(self.closeReason ?? .idleTimeout))
    }

    // MARK: Keepalive

    /// Starts, changes or stops (`nil`) the keepalives.
    public mutating func setKeepAliveInterval(_ interval: NetworkDuration?, now: NetworkClock.Instant) {
        self.keepAliveInterval = interval.flatMap { $0 > .zero ? $0 : nil }
        self.rearmKeepAlive(now: now)
    }

    /// Schedules the next keepalive an interval from `now`, once the handshake completed.
    mutating func rearmKeepAlive(now: NetworkClock.Instant) {
        guard let interval = self.keepAliveInterval, self.handshake.isComplete, !self.isClosingOrDraining else {
            self.keepAliveDeadline = nil
            return
        }
        if let idleTimeout = self.idleTimeout, interval >= idleTimeout {
            // The connection would idle out first.
            self.keepAliveDeadline = nil
            return
        }
        self.keepAliveDeadline = now.advanced(by: interval)
    }

    private mutating func keepAliveTimerFired(now: NetworkClock.Instant) {
        let limit = self.configuration.maxUnacknowledgedKeepAlives
        if limit > 0 && self.unacknowledgedKeepAlives >= limit {
            self.log.error("Closing after \(self.unacknowledgedKeepAlives) unacknowledged keepalives")
            self.keepAliveDeadline = nil
            self.closeReason = .keepAliveTimeout
            self.startClosing(
                PendingClose(
                    errorCode: CoreTransportError.noError,
                    isApplication: false,
                    frameType: 0,
                    reason: "keepalive limit reached"
                ),
                now: now
            )
            return
        }
        self.keepAlivePending = true
        self.unacknowledgedKeepAlives &+= 1
        self.rearmKeepAlive(now: now)
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
        guard self.streams.streams[streamID]?.canSend == true, self.streams.streams[streamID]?.resetCode == nil else {
            return
        }
        self.streams.streams[streamID]!.send.finish()
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

    /// The limit on the streams of one kind the peer may open, as last raised.
    public func localMaxStreams(bidirectional: Bool) -> UInt64 {
        bidirectional ? self.streams.localMaxStreamsBidirectional : self.streams.localMaxStreamsUnidirectional
    }

    /// The peer's limit on the streams of one kind this endpoint may open.
    public func peerMaxStreams(bidirectional: Bool) -> UInt64 {
        bidirectional ? self.streams.peerMaxStreamsBidirectional : self.streams.peerMaxStreamsUnidirectional
    }

    /// Lets the peer open streams of one kind up to `maximum`, sending MAX_STREAMS. A limit
    /// can't shrink, so a lower value changes nothing.
    public mutating func raiseLocalMaxStreams(to maximum: UInt64, bidirectional: Bool) {
        guard !self.isClosingOrDraining, maximum <= (1 << 60) else { return }
        self.streams.raiseLocalMaxStreams(to: maximum, bidirectional: bidirectional)
    }

    // MARK: Datagrams

    /// The largest payload ``sendDatagram(_:)`` accepts: what fits a 1-RTT packet and the peer's
    /// `max_datagram_frame_size`. Zero if the peer doesn't accept DATAGRAM frames, or before its
    /// transport parameters arrived.
    public var maxDatagramPayloadSize: Int {
        let peerLimit = self.peerMaxDatagramFrameSize
        guard peerLimit > 0 else { return 0 }
        // A short header with the longest packet number, and the tag.
        let packetOverhead = 1 &+ self.peerConnectionID.length &+ 4 &+ Self.tagLength
        let frameLimit = min(peerLimit, self.maxDatagramSize &- packetOverhead)
        // The frame type and the length field.
        return max(0, frameLimit &- 1 &- CoreWriter.vleLength(UInt64(max(0, frameLimit))))
    }

    /// Queues a DATAGRAM frame. Returns `false` if the peer doesn't accept one this large, or
    /// the connection is closing.
    ///
    /// Datagrams queued before the handshake completes wait for the peer's limit.
    @discardableResult
    public mutating func sendDatagram(_ payload: RawSpan) -> Bool {
        guard !self.isClosingOrDraining else { return false }
        if self.peerTransportParameters != nil {
            guard payload.byteCount <= self.maxDatagramPayloadSize else { return false }
        }
        if self.datagramsToSend.count >= Self.maximumQueuedDatagrams {
            self.datagramsToSend.removeFirst()
        }
        self.datagramsToSend.append([UInt8](copying: payload))
        return true
    }

    /// Calls `body` with the oldest DATAGRAM payload received, and forgets it. Returns `nil` if
    /// there is none.
    public mutating func readDatagram<Result>(_ body: (RawSpan) -> Result) -> Result? {
        guard let payload = self.datagramsReceived.popFirst() else { return nil }
        return body(payload.span.bytes)
    }

    /// Starts a key update: 1-RTT packets are sent with the next generation of keys (RFC 9001
    /// Section 6). Returns `false` before the handshake is confirmed, and while the peer hasn't
    /// sent a packet in the current key phase, which means it hasn't followed the last update yet.
    @discardableResult
    public mutating func updateKeys() -> Bool {
        guard self.isHandshakeConfirmed, !self.isClosingOrDraining, self.keyPhaseFirstReceived != nil else {
            return false
        }
        self.protector.trafficUpdate(previousKeyState: self.keyPhase)
        self.keyPhase = self.keyPhase == .phase0 ? .phase1 : .phase0
        self.keyPhaseFirstReceived = nil
        return true
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
    /// The ECN codepoints of the packets received, which the ACK frames report.
    var ecnCounts = CoreECNCounts()

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
        // ACK_ECN once a packet arrived with an ECN codepoint (RFC 9000 Section 19.3).
        let ecnCounts = self.ecnCounts
        let hasECN = !ecnCounts.isZero
        var ok = writer.vle(hasECN ? 0x03 : 0x02) && writer.vle(largest) && writer.vle(delay)
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
        if hasECN {
            ok = ok && writer.vle(ecnCounts.ect0) && writer.vle(ecnCounts.ect1) && writer.vle(ecnCounts.ce)
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
        if !self.ecnCounts.isZero {
            length &+= CoreWriter.vleLength(self.ecnCounts.ect0) &+ CoreWriter.vleLength(self.ecnCounts.ect1)
            length &+= CoreWriter.vleLength(self.ecnCounts.ce)
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

    /// Whether the connection has nothing to do until the peer or the application acts: no
    /// ack-eliciting packet in flight, nothing to send, and no acknowledgement owed.
    public var isQuiescent: Bool {
        guard !self.recovery.hasAckElicitingInFlight else { return false }
        for space in PacketNumberSpace.allCases where !self.spaceDiscarded[Int(space.rawValue)] {
            if self.acks[space].ackNeeded || self.acks[space].ackDeadline != nil {
                return false
            }
            if self.handshake.send[space].hasDataToSend || self.probesPending[Int(space.rawValue)] > 0 {
                return false
            }
        }
        return !self.hasApplicationFramesToSend
    }
}
