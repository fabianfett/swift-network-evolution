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
import BasicContainers
internal import DequeModule
#endif

#if canImport(Glibc)
import Glibc
internal import Logging
#elseif canImport(Android)
import Android
internal import Logging
#elseif canImport(Musl)
import Musl
internal import Logging
#elseif canImport(os)
internal import os
#endif

#if IMPORT_SWIFTTLS && canImport(SwiftTLS)
#if EXPORT_SWIFTTLS
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS
#else
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) @_weakLinked internal import SwiftTLS
#endif
#endif

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public enum QUICConnectionState: CustomStringConvertible {
    case invalid

    // Server only when parsing
    case idle

    // Server
    case versionSent
    case retrySent
    case initialReceived
    case initialProcessed

    // Client
    case versionReceived
    case initialSent
    case retryReceived

    // Client & Server
    case handshake
    case connected

    // Termination
    case closing
    case draining

    public var description: String {
        switch self {
        case .invalid: return "invalid"
        case .idle: return "idle"
        case .versionSent: return "versionSent"
        case .retrySent: return "retrySent"
        case .initialReceived: return "initialReceived"
        case .initialProcessed: return "initialProcessed"
        case .versionReceived: return "versionReceived"
        case .initialSent: return "initialSent"
        case .retryReceived: return "retryReceived"
        case .handshake: return "handshake"
        case .connected: return "connected"
        case .closing: return "closing"
        case .draining: return "draining"
        }
    }

    func isValidStateChange(to newState: QUICConnectionState, logIDString: String) -> Bool {
        switch (self, newState) {
        case (.invalid, .idle),
            (.idle, .initialReceived),
            (.idle, .initialSent),
            (.idle, .retrySent),
            (.idle, .versionSent),
            (.versionSent, .retrySent),
            (.versionSent, .closing),
            (.versionSent, .draining),
            (.versionSent, .initialReceived),
            (.versionReceived, .closing),
            (.versionReceived, .initialSent),
            (.versionReceived, .draining),
            (.initialSent, .versionReceived),
            (.initialSent, .retryReceived),
            (.initialSent, .handshake),
            (.initialSent, .closing),
            (.initialSent, .draining),
            (.initialReceived, .initialProcessed),
            (.initialReceived, .handshake),
            (.initialReceived, .closing),
            (.initialReceived, .draining),
            (.initialProcessed, .handshake),
            (.initialProcessed, .closing),
            (.initialProcessed, .draining),
            (.retryReceived, .initialSent),
            (.retryReceived, .draining),
            (.retrySent, .initialReceived),
            (.retrySent, .draining),
            (.handshake, .connected),
            (.handshake, .closing),
            (.handshake, .draining),
            (.connected, .closing),
            (.connected, .draining),
            (.closing, .draining):
            return true
        default:
            Logger.proto.fault(
                "\(logIDString) Invalid connection state transition: \(self) -> \(newState)"
            )
            return false
        }
    }

    mutating func change(to newState: QUICConnectionState, logIDString: String) {
        #if !DisableDebugLogging
        let loggableSelf = self
        Logger.proto.debug(
            "\(logIDString) connection state transition: \(loggableSelf) -> \(newState)"
        )
        #endif
        _ = isValidStateChange(to: newState, logIDString: logIDString)
        self = newState
    }

    var isTerminal: Bool {
        switch self {
        case .closing, .draining:
            return true
        default:
            return false
        }
    }

    var isConnected: Bool {
        switch self {
        case .connected, .closing, .draining:
            return true
        default:
            return false
        }
    }
}

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public final class QUICConnection: ManyToManyApplicationStreamProtocol,
    ManyToManyApplicationDatagramProtocol, ManyToManyOutboundDatagramProtocol,
    StreamListenerHandler, HeterogeneousManyToManyProtocolHandler, TimerSchedulable
{
    public var inboundFlowLinkage = UpperProtocol()
    public var secondaryInboundFlowLinkage = SecondaryUpperProtocol()

    public var multiplexedFlows = [MultiplexedFlowIdentifier: Flow]()
    public var multiplexedSecondaryFlows = [MultiplexedFlowIdentifier: SecondaryFlow]()
    public var multiplexingPaths = [MultiplexingPathIdentifier: Path]()

    public typealias StreamFamily = BaseStreamLinkageFamily
    public typealias DatagramFamily = BaseDatagramLinkageFamily

    public typealias Flow = QUICStreamInstance
    public typealias UpperProtocol = StreamFamily.InboundFlow

    public typealias SecondaryFlow = QUICDatagramFlow
    public typealias SecondaryUpperProtocol = DatagramFamily.InboundFlow

    public typealias Path = QUICPath

    public var identifier: InstanceIdentifier

    public var log = NetworkLoggerState()
    var logPrefixer: LogPrefixer

    public private(set) var context: NetworkContext

    public var eventManager = ProtocolEventManager()
    public let timerReference = TimerReference()

    public var state: QUICConnectionState = .invalid

    var connectionMetadata = QUICConnectionProtocol.QUICConnectionMetadata()

    var timer: Timer

    var handshakeStartTime: NetworkClock.Instant = .zero
    var handshakeDuration: NetworkDuration = .zero

    /// The keepalive interval the application set, which a core created later picks up.
    var keepaliveDuration: NetworkDuration = .zero

    /// A continuous and an absolute reading of the clock, taken back to back.
    struct ClockSample {
        let continuous: NetworkClock.Instant
        let absolute: NetworkClock.Instant
    }

    /// The readings pinned by `withPinnedClock`, or `nil` outside it.
    ///
    /// Paced departure times are converted between the two clock domains by subtracting one reading
    /// from the other, so the pair must be sampled together.
    var pinnedClock: ClockSample?

    @_optimize(speed)
    @inline(always)
    var now: NetworkClock.Instant {
        pinnedClock?.continuous ?? context.now
    }

    @_optimize(speed)
    @inline(always)
    var nowAbsolute: NetworkClock.Instant {
        pinnedClock?.absolute ?? context.nowAbsolute
    }

    /// Runs `body` with the clock pinned, so everything inside it sees one pair of readings.
    ///
    /// The outermost call takes the pin and releases it on the way out. One nested inside
    /// another keeps the outer call's readings, so `now` holds still for the whole batch.
    /// Code that needs real elapsed time within a batch reads `context.now` directly.
    @inline(always)
    func withPinnedClock(_ body: () -> Void) {
        if pinnedClock != nil {
            body()
            return
        }
        pinnedClock = ClockSample(continuous: context.now, absolute: context.nowAbsolute)
        defer { pinnedClock = nil }
        body()
    }

    var logIDNumber: Int = 0
    let signpostID = QUICSignpost.makeSignpostID()

    // Initial version set by client or server
    var initialVersion: QUICVersion? = Constants.defaultVersion
    // The final QUIC version negotiated
    var negotiatedVersion: QUICVersion?
    // Used to return the most up to date version
    public var currentVersion: QUICVersion {
        // If negotiated version is set then this is the final version
        if let negotiatedVersion {
            return negotiatedVersion
        }
        return initialVersion ?? .v1
    }
    /// Has no effect: the core reads `QUICConnectionOptions.forceUnsupportedClientVersion`.
    public var forceUnsupportedClientVersion: Bool = false

    // MARK: Streams

    var unidirectionalStreams = QUICStreamIDState(.unidirectional)
    var bidirectionalStreams = QUICStreamIDState(.bidirectional)

    var knownFlows = [QUICStreamID: MultiplexedFlowIdentifier]()

    var localCIDLength: Int = 0  // would be private(set)
    private var initialSourceConnectionID: QUICConnectionID?
    private var initialStatelessResetToken: QUICStatelessResetToken?

    fileprivate var flowsHaveEverMarkedIdle = false

    // MARK: Path

    var currentPath: QUICPath?

    private(set) var initialMSS = Constants.initialMSS
    private(set) var pathPropertiesMTU = 0

    // MARK: Logging
    public var qlogConfiguration: QLogConfiguration?
    private(set) var qLog: QLog?

    var stats: Statistics

    var logIDString: String { self.log.logPrefix }
    var initialInterface: Interface? = nil

    // MARK: Flags

    private(set) var isServer = false
    private(set) var spinBitEnabled = false
    private(set) var initialSpinValue = false
    private(set) var retryEnabled = false
    var migrationSupported = false

    var pendOutboundData = false  // Don't immediately process application sends

    // false == IPv6, true == IPv4
    private(set) var initialAddressIsIPv4 = false

    /// Has no effect: the core paces as `QUICConnectionOptions.enablePacing` says.
    public var pacingEnabled: Bool = false

    private(set) var datagramUseQuarterStreamID = false
    var datagramUseContextID = false
    var datagramEnableFlowID = false

    private(set) var maximumConcurrentBidirectionalStreams: Int?
    private(set) var maximumConcurrentUnidirectionalStreams: Int?

    var originalDCID: QUICConnectionID
    var initialDCID: QUICConnectionID?
    var initialToken: [UInt8]?

    // The error code and reason sent/received in a CONNECTION_CLOSE frame.
    public var closeError: QUICTransportError?
    var receivedConnectionClose = false

    // The error code and reason sent/received in an APPLICATION_CLOSE frame.
    public var applicationCloseError: QUICApplicationError?
    var receivedApplicationClose = false
    #if NETWORK_PRIVATE
    var privateStorage = QUICConnectionPrivateStorage()
    #endif

    // The error to be reported to app when draining or
    // closing the connection.
    var errorToReport: NetworkError?

    // MARK: Core

    var coreConfiguration: QUICConnectionCore.Configuration?
    /// The core, once a client started its handshake or a server got the client's first packet.
    var coreBox: QUICConnectionCoreBox?
    var coreTimerID: Timer.TimerID?
    var coreStatelessResetToken: QUICStatelessResetToken?
    /// Whether the application was told the connection is gone.
    var coreReportedClose = false
    /// Set while `coreAfterUpdate` runs, which the application may re-enter.
    var coreIsUpdating = false
    var coreUpdatePending = false
    /// How often `coreAfterUpdate` ran, for tests.
    var coreAfterUpdateRuns = 0
    /// The core's name for each path; the path of the handshake is `.initial`.
    var corePathIDs: [MultiplexingPathIdentifier: CorePathID] = [:]
    var coreNextPathID = 1
    /// What the establishment report says once the core is gone.
    var coreLastHandshakeRTT: NetworkDuration?
    var coreLastL4SEnabled = false

    public convenience init(context: NetworkContext) {
        self.init(context: context, in: &context.eventContext)
    }

    public init(context: NetworkContext, in eventContext: inout NetworkContext.EventContext) {
        self.context = context
        self.logPrefixer = LogPrefixer("[C?]")

        let defaultServerCIDLength = 8
        self.originalDCID = QUICConnectionID(defaultServerCIDLength)
        self.stats = Statistics()
        self.identifier = InstanceIdentifier(
            eventManager: &self.eventManager,
            in: &eventContext
        )
        self.timer = Timer(
            identifier: self.identifier,
            context: context,
            timerReference: timerReference,
            logPrefixer: logPrefixer
        )
    }

    public func setup(
        remote: Endpoint?,
        local: Endpoint?,
        parameters: Parameters?,
        path: PathProperties?
    ) throws(NetworkError) {
        #if NETWORK_PRIVATE
        self.privateStorage.setupFlowRegistration(path)
        #endif
        self.isServer = parameters?.isServer ?? false
        self.logPrefixer.log.logPrefix = self.log.logPrefix
        self.initialInterface = path?.directInterface ?? nil
        self.logPrefixer.logIDString = ""

        state.change(to: .idle, logIDString: logPrefixer.logIDString)

        // Setup metadata callbacks
        self.setMetadataHandlers()

        if let remote, case .address(let remoteAddress) = remote.type,
            case .v4 = remoteAddress.type
        {
            initialAddressIsIPv4 = true
        }

        if let path {
            pathPropertiesMTU = path.mtu
        }

        if let parameters,
            let quicOptions = quicOptions(from: parameters, for: .allFlows),
            let protocolOptions = quicOptions.perProtocolOptions
        {
            let quicConnectionOptions = protocolOptions.quicConnectionOptions
            self.logIDNumber = quicOptions.logIDNumber ?? 0
            if isServer {
                // The core sends the stateless reset token of `connect` (`coreConnect`).
                retryEnabled = quicConnectionOptions.retry
            } else {
                // A client can force version negotiation by setting the initial version to the negotiationPattern (0x?a?a?a?a)
                if quicConnectionOptions.forceVersionNegotiation {
                    self.initialVersion = .negotiationPattern
                    log.info("Setting negotiation pattern")
                }
            }
            if let initialSCID = quicConnectionOptions.initialSourceConnectionID {
                initialSourceConnectionID = initialSCID
            }
            if let statelessResetToken = quicConnectionOptions
                .initialStatelessResetToken
            {
                initialStatelessResetToken = statelessResetToken
            }
            // RFC 9000 - 14.1. Initial Datagram Size
            // Datagrams containing Initial packets MAY exceed 1200 bytes if the sender
            // believes that the network path and peer both support the size that it chooses
            let requestedInitialPacketSize = Int(quicConnectionOptions.initialPacketSize)
            if requestedInitialPacketSize > Constants.initialMSS {
                initialMSS = requestedInitialPacketSize
            }

            pacingEnabled = quicConnectionOptions.enablePacing

            forceUnsupportedClientVersion = quicConnectionOptions.forceUnsupportedClientVersion

            qlogConfiguration = quicConnectionOptions.qlogConfiguration

            datagramUseQuarterStreamID =
                quicConnectionOptions.datagramQuarterStreamID
            datagramUseContextID = quicConnectionOptions.datagramContextID
            datagramEnableFlowID = quicConnectionOptions.datagramEnableFlowID

            maximumConcurrentBidirectionalStreams =
                quicConnectionOptions.maximumConcurrentBidirectionalStreams
            maximumConcurrentUnidirectionalStreams =
                quicConnectionOptions.maximumConcurrentUnidirectionalStreams

            if !quicConnectionOptions.disableSpinBit {
                // RFC9000: "Even when the spin bit is not disabled by
                // the administrator, endpoints MUST disable their use
                // of the spin bit for a random selection of at least
                // one in every 16 network paths, or for one in every
                // 16 connection IDs, in order to ensure that QUIC
                // connections that disable the spin bit are commonly
                // observed on the network."
                var randomNumberGenerator = SystemRandomNumberGenerator()
                spinBitEnabled = UInt8.random(in: 0..<16, using: &randomNumberGenerator) > 0
                if !spinBitEnabled {
                    // It's recommended that the spin value is set
                    // to a random value when we are not using the spin bit.
                    initialSpinValue = UInt8.random(in: 0...1) > 0
                }
            } else {
                // The application has asked us to disable the spin bit.
                spinBitEnabled = false
                initialSpinValue = quicConnectionOptions.spinBitValue
            }
            // The core sets up its transport parameters, ECN, L4S and pacing from the
            // configuration.
            self.coreConfiguration = self.makeCoreConfiguration(
                quicOptions: quicOptions,
                tlsOptions: quicOptions.tlsOptions
            )
        }
        #if QlogOutput
        // There are 2 ways to setup a Qlog directory, one through the configuration and one through Preferences
        if qlogConfiguration == nil && QUICPreferences.shared.quiclogDirectory != "" {
            qlogConfiguration = QLogConfiguration(logPath: QUICPreferences.shared.quiclogDirectory)
        }
        // Only setup qlog if the directory is set
        if let qlogConfiguration {
            self.qLog = QLog(configuration: qlogConfiguration, context: context)
            log.info("QLog setup with configuration: \(qlogConfiguration)")
        }
        #endif
        log.info("Setup QUIC connection (spin bit \(spinBitEnabled ? "enabled" : "disabled"))")
    }

    public func setup(
        flow flowID: MultiplexedFlowIdentifier,
        remote: Endpoint?,
        local: Endpoint?,
        parameters: Parameters?,
        path: PathProperties?
    ) throws(NetworkError) {

        guard let parameters,
            let quicOptions = quicOptions(from: parameters, for: flowID),
            let protocolOptions = quicOptions.perProtocolOptions
        else {
            throw NetworkError.posix(EINVAL)
        }

        if protocolOptions.isDatagram {
            guard let datagramFlow = secondaryFlow(for: flowID) else {
                throw NetworkError.posix(ENOENT)
            }
            setupNewDatagramFlow(datagramFlow, with: protocolOptions)
        } else {
            guard let stream = flow(for: flowID) else {
                throw NetworkError.posix(ENOENT)
            }
            setupNewOutboundStream(stream, with: protocolOptions)
        }
    }

    deinit {
        self.qLog = nil
    }

    func setMSS(_ newMSS: Int, on path: QUICPath) {
        if _slowPath(newMSS < Constants.initialMSS) {
            path.mss = Constants.initialMSS
        } else if path.maximumMSS > Constants.initialMSS && newMSS > path.maximumMSS {
            path.mss = path.maximumMSS
        } else if newMSS < path.initialMSS {
            path.mss = path.initialMSS
        } else {
            path.mss = newMSS
        }
        // The core's congestion controller follows its own datagram size.
        if path == currentPath {
            applyToAllSecondaryFlows { datagramFlow in
                self.coreUpdateUsableDatagramSize(datagramFlow)
            }
        }
    }

    func setInitialMSS(on path: QUICPath) {
        setMSS(initialMSS, on: path)
    }

    func updateMaxBidirectionalStreamsFromApplication(
        _ maximumStreams: Int,
        in eventContext: inout NetworkContext.EventContext
    ) {
        self.coreRaiseLocalMaxStreams(maximumStreams, bidirectional: true, in: &eventContext)
    }

    func updateMaxUnidirectionalStreamsFromApplication(
        _ maximumStreams: Int,
        in eventContext: inout NetworkContext.EventContext
    ) {
        self.coreRaiseLocalMaxStreams(maximumStreams, bidirectional: false, in: &eventContext)
    }

    func setMetadataHandlers() {

        // Set handlers

        #if !NETWORK_EMBEDDED
        // Setup the local_max_streams_bidirectional_handler
        // These metadata handlers are invoked by the application, so they are genuine entry
        // points into the stack and acquire the event context here.
        self.connectionMetadata.setLocalMaxStreamsBidirectional { maxStreams in
            self.fromExternal { eventContext in
                self.updateMaxBidirectionalStreamsFromApplication(Int(maxStreams), in: &eventContext)
            }
        }

        self.connectionMetadata.setLocalMaxStreamsUnidirectional { (maxStreams: UInt64) in
            self.fromExternal { eventContext in
                self.updateMaxUnidirectionalStreamsFromApplication(Int(maxStreams), in: &eventContext)
            }
        }

        self.connectionMetadata.setKeepalive { (keepaliveSeconds: UInt16) in
            self.fromExternal { eventContext in
                if keepaliveSeconds == Constants.defaultKeepaliveValue {
                    self.keepaliveConfigure(
                        duration: Constants.defaultKeepaliveDuration,
                        in: &eventContext
                    )
                } else {
                    self.keepaliveConfigure(
                        duration: .seconds(keepaliveSeconds),
                        in: &eventContext
                    )
                }
            }
        }

        // Get handlers
        self.connectionMetadata.getLocalMaxStreamsBidirectional {
            self.coreBox?.core.localMaxStreams(bidirectional: true) ?? 0
        }
        self.connectionMetadata.getLocalMaxStreamsUnidirectional {
            self.coreBox?.core.localMaxStreams(bidirectional: false) ?? 0
        }
        self.connectionMetadata.getRemoteMaxStreamsBidirectional {
            self.coreBox?.core.peerMaxStreams(bidirectional: true) ?? 0
        }
        self.connectionMetadata.getRemoteMaxStreamsUnidirectional {
            self.coreBox?.core.peerMaxStreams(bidirectional: false) ?? 0
        }
        self.connectionMetadata.getKeepalive {
            let keepaliveSeconds = self.keepaliveDuration.seconds
            return UInt16(keepaliveSeconds)
        }

        self.connectionMetadata.getLocalConnectionIDs {
            self.coreBox?.core.connectionIDs.local.map(\.connectionID) ?? []
        }
        #endif
    }

    func unsetMetadataHandlers(
        on metadata: QUICConnectionProtocol.QUICConnectionMetadata? = nil
    ) {
        #if !NETWORK_EMBEDDED
        let metadata = metadata ?? self.connectionMetadata
        // Explicitly break any strongly captured references to self from setMetadataHandlers
        metadata.setKeepaliveHandler = nil
        metadata.getKeepaliveHandler = nil
        metadata.setLocalMaxStreamsBidirectionalHandler = nil
        metadata.setLocalMaxStreamsUnidirectionalHandler = nil
        metadata.getLocalMaxStreamsBidirectionalHandler = nil
        metadata.getLocalMaxStreamsUnidirectionalHandler = nil
        metadata.getRemoteMaxStreamsBidirectionalHandler = nil
        metadata.getRemoteMaxStreamsUnidirectionalHandler = nil
        metadata.getLocalConnectionIDsHandler = nil
        #endif
    }

    func logTransportParameters(
        owner: QLogOwner?,
        transportParameters: TransportParameters
    ) {
        #if QlogOutput
        if let qLog {
            qLog.parametersSet(
                owner: owner,
                transportParameters: transportParameters,
                timestamp: self.now
            )
        }
        #endif
    }

    public func connect(in eventContext: inout NetworkContext.EventContext) {
        log.debug(
            "Received connection start (isServer: \(self.isServer))"
        )

        // Generate a local CID
        let scid: QUICConnectionID
        if let initialSourceConnectionID {
            if initialSourceConnectionID.isUninitialized {
                // CID was all zeros, just use the length
                scid = QUICConnectionID(initialSourceConnectionID.length)
            } else {
                scid = initialSourceConnectionID
            }
            self.initialSourceConnectionID = nil
        } else {
            let scidLength: Int
            if isServer {
                scidLength = QUICConnectionID.defaultServerSCIDLength
            } else {
                scidLength = QUICConnectionID.defaultClientSCIDLength
            }
            scid = QUICConnectionID(scidLength)
        }
        // A server with zero-length connection IDs can't follow a client that migrates, and
        // tells it so (`coreAcceptFirstDatagram`, RFC 9000 Section 5.1).
        self.localCIDLength = scid.length

        let statelessResetToken: QUICStatelessResetToken
        if let initialStatelessResetToken {
            statelessResetToken = initialStatelessResetToken
            self.initialStatelessResetToken = nil
        } else {
            statelessResetToken = .init()
        }

        // Set up the initial path
        if currentPath == nil, let initialPath = self.somePath {
            initialPath.set(interface: self.initialInterface, isInitial: true)
            log.info("Packet Pacing is \(self.coreConfiguration?.pacingEnabled == true ? "enabled" : "disabled")")
            initialPath.setSCID(scid)
            if !isServer {
                initialPath.assignDCID(originalDCID, in: &eventContext)
            }
            setInitialMSS(on: initialPath)
            currentPath = initialPath
        }

        self.coreConnect(scid: scid, statelessResetToken: statelessResetToken, in: &eventContext)
    }

    public func connect(flow flowID: MultiplexedFlowIdentifier, in eventContext: inout NetworkContext.EventContext) {
        log.debug(
            "Received connection start on flow \(flowID.debugDescription) (isServer: \(self.isServer))"
        )
        // For streams (not datagram flows), ensure the stream isn't pending
        if secondaryFlow(for: flowID) == nil {
            // If this is a QUICStream then make sure its not in a pending state
            guard let stream = flow(for: flowID), !stream.pendingStart else {
                log.error(
                    "Flow \(flowID.debugDescription) cannot go connected because it is pending (isServer: \(self.isServer))"
                )
                return
            }
        }
        deliverConnectedEvent(flow: flowID, in: &eventContext)
    }

    public func teardown(in eventContext: inout NetworkContext.EventContext) {
        close(in: &eventContext)
    }

    /// Tears down a connection built outside a protocol stack, for tests only.
    public func destroyFromExternalTest() {
        fromExternal { eventContext in
            teardown(in: &eventContext)
            for path in multiplexingPaths.values {
                var path = path
                path.destroy(in: &eventContext)
            }
            multiplexingPaths.removeAll()
            unregisterEventManager(in: &eventContext)
        }
    }

    public func disconnect(error: NetworkError?, in eventContext: inout NetworkContext.EventContext) {
        if let error {
            if closeError == nil, let transportError = error.quicTransportError {
                closeError = QUICTransportError(transportError, error.description)
            } else if applicationCloseError == nil,
                let applicationError = error.quicApplicationError
            {
                self.applicationCloseError = QUICApplicationError(
                    applicationError,
                    error.description
                )
            }
        }
        close(in: &eventContext)
    }

    public func teardown(flow: MultiplexedFlowIdentifier, in eventContext: inout NetworkContext.EventContext) {
        disconnect(flow: flow, direction: .both, in: &eventContext)
    }

    public func disconnect(
        flow: MultiplexedFlowIdentifier,
        error: NetworkError?,
        in eventContext: inout NetworkContext.EventContext
    ) {
        disconnect(flow: flow, direction: .both, error: error, in: &eventContext)
    }

    enum FlowStopDirection {
        case inbound
        case outbound
        case both
    }

    func disconnect(
        flow flowID: MultiplexedFlowIdentifier,
        direction: FlowStopDirection,
        error: NetworkError? = nil,
        in eventContext: inout NetworkContext.EventContext
    ) {
        log.debug(
            "Stopping flow \(flowID.debugDescription) (direction: \(direction))"
        )

        if let error, let applicationError = error.quicApplicationError,
            let stream = flow(for: flowID)
        {
            switch direction {
            case .inbound:
                stream.inboundApplicationError = UInt64(applicationError)
            case .outbound:
                stream.outboundApplicationError = UInt64(applicationError)
            case .both:
                stream.inboundApplicationError = UInt64(applicationError)
                stream.outboundApplicationError = UInt64(applicationError)
            }
        }
        if let stream = flow(for: flowID) {
            switch direction {
            case .both:
                handleStopRead(for: stream)
                stream.writeClosed = handleStopWrite(for: stream)
                stream.readClosed = true
            case .inbound:
                handleStopRead(for: stream)
                stream.readClosed = true
            case .outbound:
                stream.writeClosed = handleStopWrite(for: stream)
            }
            if stream.readClosed, stream.writeClosed {
                stream.close(errorCode: nil, in: &eventContext)
                stream.log.debug("Closed stream")
            } else {
                stream.log.debug(
                    "stream.readClosed \(stream.readClosed), stream.writeClosed \(stream.writeClosed)"
                )

            }
        } else if let _ = secondaryFlow(for: flowID) {
            deliverDisconnectedEvent(flow: flowID, error: nil, in: &eventContext)
        } else {
            log.error("No stream for \(flowID), cannot close")
        }

        // Possibly send STOP_SENDING, RESET_STREAM or a FIN, which the core holds until it can
        // send them.
        self.coreAfterApplicationUpdate(in: &eventContext)
    }

    public func serviceReceivedDatagrams(
        path pathID: MultiplexingPathIdentifier,
        in eventContext: inout NetworkContext.EventContext
    ) {
        self.coreServiceReceivedDatagrams(path: pathID, in: &eventContext)
    }

    func recordRxPackets(
        totalRxBytes: Int,
        totalPackets: Int,
        pathStatistics: inout Statistics,
        connectionStatistics: inout Statistics
    ) {
        connectionStatistics.increment(.rxBytes, by: totalRxBytes)
        connectionStatistics.increment(.rxPackets, by: totalPackets)
        pathStatistics.increment(.rxPackets, by: totalPackets)
        pathStatistics.increment(.rxBytes, by: totalRxBytes)
    }

    // Handle an outbound write to stream, queue the data for sending in the
    // send buffer and kick off sending from it. There is just one call with all
    // the written data.
    public func serviceStreamDataToSend(
        flow flowID: MultiplexedFlowIdentifier,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let stream = flow(for: flowID) else {
            log.error("Unable to access state for flow \(flowID)")
            return
        }

        self.coreServiceStreamDataToSend(stream, in: &eventContext)
    }

    #if !NETWORK_EMBEDDED
    public func getMetadata<P: NetworkProtocol>(
        flow flowID: MultiplexedFlowIdentifier
    ) -> ProtocolMetadata<P>? {
        guard P.self == QUICProtocol.self else {
            return nil
        }

        if case .allFlows = flowID {
            let metadata = QUICProtocol.metadata()
            metadata.perProtocolMetadata?.quicConnectionMetadata = self.connectionMetadata
            return metadata as? ProtocolMetadata<P>
        }

        if let datagramFlow = secondaryFlow(for: flowID) {
            let metadata = QUICProtocol.metadata()
            metadata.perProtocolMetadata?.datagramFlowID = datagramFlow.flowID
            metadata.perProtocolMetadata?.usableDatagramFrameSize = UInt16(
                datagramFlow.usableDatagramSize
            )
            metadata.perProtocolMetadata?.isDatagramFlow = true
            metadata.perProtocolMetadata?.quicConnectionMetadata = self.connectionMetadata
            return metadata as? ProtocolMetadata<P>
        }

        guard let stream = flow(for: flowID),
            let streamID = stream.streamID
        else {
            return nil
        }

        let metadata = QUICProtocol.metadata()
        metadata.perProtocolMetadata = stream.streamMetadata
        metadata.perProtocolMetadata?.quicConnectionMetadata = self.connectionMetadata
        metadata.perProtocolMetadata?.streamID = streamID.value
        if let streamType = stream.streamType {
            metadata.perProtocolMetadata?.streamType = streamType
        }
        return metadata as? ProtocolMetadata<P>
    }
    #endif

    public func updateDataTransferSnapshot(flow: MultiplexedFlowIdentifier, _ snapshot: inout DataTransferSnapshot) {
        snapshot.receivedTransportOutOfOrderByteCount = UInt64(clamping: self.stats[.rxOutOfOrderBytes])
        snapshot.sentTransportRetransmittedByteCount = UInt64(clamping: self.stats[.txRetransmittedBytes])
        snapshot.sentTransportECNCapablePacketCount = UInt64(clamping: self.stats[.ecnCapablePacketsSent])
        snapshot.sentTransportECNCapableAckedPacketCount = UInt64(clamping: self.stats[.ecnCapablePacketsAcknowledged])
        snapshot.sentTransportECNCapableMarkedPacketCount = UInt64(clamping: self.stats[.ecnCapablePacketsMarked])
        snapshot.sentTransportECNCapableLostPacketCount = UInt64(clamping: self.stats[.ecnCapablePacketsLost])
        // The RTT and congestion state of the active path, which the core keeps (RFC 9002
        // Sections 5 and 7).
        if let box = self.coreBox {
            snapshot.transportMinimumRTT = box.core.minRTT
            snapshot.transportSmoothedRTT = box.core.smoothedRTT
            snapshot.transportCurrentRTT = box.core.latestRTT
            snapshot.transportRTTVariance = box.core.rttVariance
            snapshot.transportCongestionWindow = UInt64(clamping: box.core.congestionWindow)
            // No congestion event yet: the threshold is infinite.
            let slowStartThreshold = box.core.slowStartThreshold
            snapshot.transportSlowStartThreshold =
                slowStartThreshold == .max ? .max : UInt64(clamping: slowStartThreshold)
        }
    }

    public var protocolEstablishmentReport: ProtocolEstablishmentReport? {
        let clientAccurateECNState = self.coreClientAccurateECNState
        // A core that is gone keeps the values the application read before.
        let l4sEnabled = self.coreBox?.core.l4sEnabled ?? self.coreLastL4SEnabled
        let handshakeRTT = self.coreBox?.core.handshakeRTT ?? self.coreLastHandshakeRTT
        var protocolEstablishmentReport = ProtocolEstablishmentReport(
            handshakeDuration: handshakeDuration,
            handshakeRTT: handshakeRTT ?? .zero,
            protocolIdentifier: QUICConnectionProtocol.identifier,
            clientAccurateECNState: clientAccurateECNState
        )
        protocolEstablishmentReport.l4sEnabled = l4sEnabled
        protocolEstablishmentReport.quicMigrationSupported = migrationSupported
        protocolEstablishmentReport.quicStatelessResetReceived = (self.stats[.statelessResetReceived] > 0)
        protocolEstablishmentReport.quicStatelessResetDuringPathProbe = (self.stats[.statelessResetDuringPathProbe] > 0)

        return protocolEstablishmentReport
    }

    func setupNewOutboundStream(
        _ stream: Flow,
        with protocolOptions: QUICStreamProtocol.Options
    ) {
        self.coreSetupNewOutboundStream(stream, with: protocolOptions)
    }

    /// Closes the connection from outside the protocol stack.
    ///
    /// Almost all closes originate inside the stack and should thread their own state into
    /// `close(in:)`. This entry point is for callers that are genuinely
    /// external to the stack and therefore have to acquire the state themselves.
    public func closeFromExternal() {
        fromExternal { eventContext in
            close(in: &eventContext)
        }
    }

    // Closing all flows, i.e. streams, and the connection itself
    func close(in eventContext: inout NetworkContext.EventContext) {
        self.coreClose(in: &eventContext)
    }

    func keepaliveConfigure(
        duration: NetworkDuration,
        in eventContext: inout NetworkContext.EventContext
    ) {
        if keepaliveDuration == .zero && duration == .zero {
            // Nothing to enable/disable.
            return
        }
        keepaliveDuration = duration
        // A core created later picks the interval up from `keepaliveDuration`.
        self.coreBox?.core.setKeepAliveInterval(duration, now: self.now)
        self.coreAfterUpdate(in: &eventContext)
    }

    public func handleOutboundRoomAvailableEvent(
        path pathID: MultiplexingPathIdentifier,
        in eventContext: inout NetworkContext.EventContext
    ) {
        self.coreAfterUpdate(in: &eventContext)
    }

    func recordTxPackets(
        totalTxBytes: Int,
        totalPackets: Int,
        pathStatistics: inout Statistics,
        connectionStatistics: inout Statistics
    ) {
        connectionStatistics.increment(.txBytes, by: totalTxBytes)
        connectionStatistics.increment(.txPackets, by: totalPackets)
        pathStatistics.increment(.txPackets, by: totalPackets)
        pathStatistics.increment(.txBytes, by: totalTxBytes)
    }

    internal func handleStopRead(for stream: Flow) {
        if stream.readClosed {
            // Already handled
            return
        }
        stream.log.debug("Read closed")
        self.coreStopRead(stream)
    }

    internal func handleStopWrite(
        for stream: Flow
    ) -> Bool {
        stream.log.debug("Write closed for stream")
        return self.coreStopWrite(stream)
    }

    func writeQLog(in eventContext: inout NetworkContext.EventContext) {
        #if QlogOutput
        if let qLog {
            guard let configuration = qLog.configuration
            else {
                return
            }
            eventContext.async {
                var flowType: QLogFlowType = .client
                var applicationType = "client"
                if self.isServer {
                    flowType = .server
                    applicationType = "server"
                }
                let title = configuration.logTitle ?? ""
                let connectionID = "C\(self.logIDNumber)"
                var filename = "qlog_\(applicationType)_\(connectionID).qlog"
                if title != "" {
                    filename = "qlog_\(applicationType)_\(title)_\(connectionID).qlog"
                }
                var finalPath: String
                if configuration.logPath.hasSuffix("/") {
                    finalPath = configuration.logPath + filename
                } else {
                    finalPath = configuration.logPath + "/\(filename)"
                }
                qLog.dumpJSONToFile(atPath: finalPath, forFlowType: flowType)
                self.log.info("Wrote qlog file to: \(finalPath)")
            }
        }
        #endif
    }

    public func wakeup(in eventContext: inout NetworkContext.EventContext) {
        // Outside a batch neither timestamp cache is set, so `self.now` falls through to a clock
        // read.
        self.timer.timerFired(at: self.now, in: &eventContext)
    }

    func deliverInboundAbortedEvent(
        stream: Flow,
        error: NetworkError?,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let streamID = stream.streamID,
            let _ = knownFlows[streamID]
        else {
            log.error("Cannot deliver inbound aborted event: no flow for stream \(stream.streamID?.value ?? 0)")
            return
        }
        stream.deliverInboundAbortedEvent(error: error, in: &eventContext)
    }

    func handleStreamClose(
        stream: Flow,
        error: NetworkError?,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let streamID = stream.streamID,
            let flowID = knownFlows[streamID]
        else {
            return
        }
        stream.upperReceiveQueue.finalizeAllFramesAsFailed()
        stream.closed = true
        deliverDisconnectedEvent(flow: flowID, error: error, in: &eventContext)
        knownFlows.removeValue(forKey: streamID)
        self.coreReturnStreamCredit(streamID)
    }
}

// MARK: Flow Control - Outbound Frame Processing

@available(Network 0.1.0, *)
extension QUICConnection {

    func sendVersionNegotiation(
        packet: borrowing Packet,
        path: QUICPath,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let scid = packet.sourceConnectionID,
            let dcid = packet.destinationConnectionID
        else {
            log.error("Failed to parse dcid / scid values from packet")
            return
        }
        // N.B.: The packet scid/dcid are swapped when constructing QUICVersionNegotiation
        sendVersionNegotiation(destinationConnectionID: scid, sourceConnectionID: dcid, path: path, in: &eventContext)
    }

    /// Sends a Version Negotiation packet listing the versions this endpoint supports.
    func sendVersionNegotiation(
        destinationConnectionID: QUICConnectionID,
        sourceConnectionID: QUICConnectionID,
        path: QUICPath,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let initialVersion = self.initialVersion else {
            log.error("Failed to send version negotiation due to a missing initial version")
            return
        }
        let supportedVersions: [QUICVersion] = [initialVersion, .negotiationPattern]

        // Version Negotiation packets are special, they are not a specific frame type and they do not sealed so they can be sent as a one-off.
        guard
            let versionNegotiation = try? QUICVersionNegotiation(
                destinationConnectionID: destinationConnectionID,
                sourceConnectionID: sourceConnectionID,
                supportedVersions: supportedVersions
            )
        else {
            log.error("Failed to create QUICVersionNegotiation")
            return
        }

        let requestedFrameLength = versionNegotiation.header.count
        guard
            var outFrames = try? getDatagramsToSend(
                path: path.pathIdentifier,
                maximumDatagramCount: 1,
                minimumDatagramSize: requestedFrameLength,
                in: &eventContext
            ),
            var outFrame = outFrames.popFirst()
        else {
            log.debug("QUIC path failed to get a frame")
            return
        }

        let frameLength = outFrame.unclaimedLength
        guard frameLength >= requestedFrameLength else {
            log.error("Invalid frame length")
            outFrame.finalize(success: false)
            return
        }
        if frameLength > requestedFrameLength {
            _ = outFrame.collapse(to: requestedFrameLength)
        }

        guard let _ = try? versionNegotiation.write(outputFrame: &outFrame, claim: false) else {
            log.error("Failed to write version negotiation frame")
            outFrame.finalize(success: false)
            return
        }

        var sendPath = path
        sendPath.enqueueOutboundDatagram(outFrame)
        sendPath.serviceLowerSendQueue(in: &eventContext)
        log.info("Sent version negotiation packet")
    }

    func sendRetry(
        path: QUICPath,
        packet: borrowing Packet,
        in eventContext: inout NetworkContext.EventContext
    ) {

        guard let packetSCID = packet.sourceConnectionID,
            let packetDCID = packet.destinationConnectionID
        else {
            log.error("Failed to parse CIDs from packet")
            return
        }
        guard let version = packet.version
        else {
            log.error("Failed to parse version value from packet")
            return
        }
        guard let scid = path.scid
        else {
            log.error("Failed to path dcid value from path")
            return
        }
        guard let _token = initialToken
        else {
            log.error("Failed to obtain token for retry")
            return
        }
        sendRetry(
            version: version,
            destinationConnectionID: packetSCID,
            sourceConnectionID: scid,
            originalDestinationConnectionID: packetDCID,
            token: _token,
            path: path,
            in: &eventContext
        )
    }

    /// Sends a Retry packet carrying `token`, as the answer to an Initial addressed to
    /// `originalDestinationConnectionID`.
    func sendRetry(
        version: QUICVersion,
        destinationConnectionID: QUICConnectionID,
        sourceConnectionID: QUICConnectionID,
        originalDestinationConnectionID: QUICConnectionID,
        token: [UInt8],
        path: QUICPath,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard
            let retryPacket = try? QUICRetryPacket(
                version: version,
                destinationConnectionID: destinationConnectionID,
                sourceConnectionID: sourceConnectionID,
                originalDCID: originalDestinationConnectionID,
                token: token
            )
        else {
            log.error("Failed to create QUICRetryPacket")
            return
        }
        let requestedFrameLength = retryPacket.header.count
        guard
            var outFrames = try? getDatagramsToSend(
                path: path.pathIdentifier,
                maximumDatagramCount: 1,
                minimumDatagramSize: requestedFrameLength,
                in: &eventContext
            ),
            var outFrame = outFrames.popFirst()
        else {
            log.debug("QUIC path failed to get a frame")
            return
        }
        let frameLength = outFrame.unclaimedLength
        guard frameLength >= requestedFrameLength else {
            log.error("Invalid frame length")
            outFrame.finalize(success: false)
            return
        }
        if frameLength > requestedFrameLength {
            _ = outFrame.collapse(to: requestedFrameLength)
        }
        guard let _ = try? retryPacket.write(outputFrame: &outFrame, claim: false) else {
            log.error("Failed to write retry frame")
            outFrame.finalize(success: false)
            return
        }
        var sendPath = path
        sendPath.enqueueOutboundDatagram(outFrame)
        sendPath.serviceLowerSendQueue(in: &eventContext)
        log.info("Sent retry packet")
    }
}

// MARK: Flow Control - Stream

@available(Network 0.1.0, *)
extension QUICConnection {
    func withMutableQUICStreams(unidirectional: Bool, closure: (inout QUICStreamIDState) -> Void) {
        if unidirectional {
            closure(&unidirectionalStreams)
        } else {
            closure(&bidirectionalStreams)
        }
    }
}

// MARK: Datagram flow handling

@available(Network 0.1.0, *)
extension QUICConnection {
    // Handle new outbound datagrams being available.
    public func serviceDatagramsToSend(
        flow flowID: MultiplexedFlowIdentifier,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let datagramFlow = secondaryFlow(for: flowID) else {
            log.error("Unable to find datagram flow \(flowID)")
            return
        }
        self.coreServiceDatagramsToSend(datagramFlow, in: &eventContext)
    }

    func setupNewDatagramFlow(
        _ flow: QUICDatagramFlow,
        with streamOptions: QUICStreamProtocol.Options
    ) {
        let datagramFlowID: UInt64?
        if datagramEnableFlowID, let associatedStreamID = streamOptions.associatedStreamID,
            datagramUseQuarterStreamID
        {
            datagramFlowID = QUICDatagramFlow.generateFlowID(from: associatedStreamID)
        } else {
            datagramFlowID = nil
        }

        flow.setup(
            datagramFlowID: datagramFlowID,
            contextID: datagramUseContextID ? streamOptions.datagramContextID : nil,
            logPrefixer: logPrefixer
        )

        flow.log.debug(
            "Created outbound datagram flow for \(flow.flowIdentifier.debugDescription)"
        )

        self.coreUpdateUsableDatagramSize(flow)
    }
}

// MARK: Connection Idle / Reuse

@available(Network 0.1.0, *)
extension QUICConnection {

    fileprivate func handleConnectionIdleForFlow(
        _ flowID: MultiplexedFlowIdentifier,
        in eventContext: inout NetworkContext.EventContext
    ) {
        if let stream = flow(for: flowID) {
            stream.applicationMarkedIdle = true
            flowsHaveEverMarkedIdle = true
        } else if let datagramFlow = secondaryFlow(for: flowID) {
            datagramFlow.applicationMarkedIdle = true
            flowsHaveEverMarkedIdle = true
        }
        checkConnectionIdle(in: &eventContext)
    }

    fileprivate func handleConnectionReusedForFlow(
        _ flowID: MultiplexedFlowIdentifier,
        in eventContext: inout NetworkContext.EventContext
    ) {
        if let stream = flow(for: flowID) {
            stream.applicationMarkedIdle = false
        } else if let datagramFlow = secondaryFlow(for: flowID) {
            datagramFlow.applicationMarkedIdle = false
        }
        checkConnectionIdle(in: &eventContext)
    }

    fileprivate func connectionIsIdleForAllStreams() -> Bool {
        // Fast exit if no flow has marked idle
        guard flowsHaveEverMarkedIdle else {
            return false
        }

        // Check if any streams are non idle
        var someFlowIsNonIdle = false
        applyToAllFlows { stream in
            if !stream.applicationMarkedIdle {
                someFlowIsNonIdle = true
            }
        }
        if someFlowIsNonIdle {
            return false
        }
        applyToAllSecondaryFlows { datagramFlow in
            if !datagramFlow.applicationMarkedIdle {
                someFlowIsNonIdle = true
            }
        }
        if someFlowIsNonIdle {
            return false
        }

        // Nothing in flight, nothing to send, and no ACK owed to the peer, either due now or
        // waiting on the delayed-ACK timer: a transmission is pending otherwise.
        return self.coreBox?.core.isQuiescent ?? true
    }

    func checkConnectionIdle(in eventContext: inout NetworkContext.EventContext) {
        // If no flow has ever been marked idle, `connectionIsIdleForAllStreams`
        // can only return false, and since `path.reportedIdleEvent` is only
        // ever set inside this function, no path can have it set either.
        // The traversal below would be a guaranteed no-op, so skip it entirely.
        guard flowsHaveEverMarkedIdle else {
            return
        }
        let isIdle = connectionIsIdleForAllStreams()
        for path in multiplexingPaths.values {
            // A path with PATH_CHALLENGE or PATH_RESPONSE to send isn't idle either.
            let corePathID = self.corePathIDs[path.pathIdentifier]
            let hasProbingFrames =
                corePathID.map { self.coreBox?.core.hasProbingFramesToSend(on: $0) ?? false } ?? false
            let pathIsIdle = isIdle && !path.isProbing && !hasProbingFrames
            if pathIsIdle && !path.reportedIdleEvent {
                // Need to report idle
                path.reportedIdleEvent = true
                path.lower.invokeApplicationEvent(event: .connectionIdle, for: path.identifier, in: &eventContext)
            } else if !pathIsIdle && path.reportedIdleEvent {
                // Need to report non-idle
                path.reportedIdleEvent = false
                path.lower.invokeApplicationEvent(event: .connectionReused, for: path.identifier, in: &eventContext)
            }
        }
    }
}

// MARK: Connection ID Lifecycle

@available(Network 0.1.0, *)
extension QUICConnection {

    public func handleApplicationEvent(
        flow flowID: MultiplexedFlowIdentifier,
        event: ApplicationEvent,
        in eventContext: inout NetworkContext.EventContext
    ) -> HandleNetworkEventResult {
        if event == .connectionIdle {
            handleConnectionIdleForFlow(flowID, in: &eventContext)
            return .consumed
        }
        if event == .connectionReused {
            handleConnectionReusedForFlow(flowID, in: &eventContext)
            return .consumed
        }
        return handleApplicationEvent(event, in: &eventContext)
    }

    public func handleApplicationEvent(
        _ event: ApplicationEvent,
        in eventContext: inout NetworkContext.EventContext
    ) -> HandleNetworkEventResult {
        if event == .outboundDataBatchStart {
            // Start pending processing
            pendOutboundData = true
            return .consumed
        }

        if event == .outboundDataBatchEnd {
            // Stop pending processing, resume sending
            pendOutboundData = false
            self.coreAfterUpdate(in: &eventContext)
            return .consumed
        }

        guard let quicEvent = event.quicEvent else {
            return .unconsumed
        }

        self.coreHandleApplicationEvent(quicEvent, in: &eventContext)
        return .consumed
    }
}

#else
@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public final class QUICConnection: ProtocolInstance {
    public private(set) var context: NetworkContext
    public init(context: NetworkContext) {
        self.context = context
        self.identifier = InstanceIdentifier(context: context, eventManager: &self.eventManager)
    }
    public var identifier: InstanceIdentifier
    public var eventManager = ProtocolEventManager()

    /// Tears down a connection built outside a protocol stack, for tests only.
    ///
    /// The stub registers an event state like the real connection does, so it has to offer the same
    /// way of handing it back: a caller that drops one while it is still registered trips a
    /// precondition in the event manager, whether or not Swift QUIC is built.
    public func destroyFromExternalTest() {
        fromExternal { eventContext in
            unregisterEventManager(in: &eventContext)
        }
    }
}
#endif
