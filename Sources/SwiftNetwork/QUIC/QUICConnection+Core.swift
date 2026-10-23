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

#if canImport(Glibc)
import Glibc
#elseif canImport(Android)
import Android
#elseif canImport(Musl)
import Musl
#elseif canImport(Darwin)
import Darwin
#endif

#if IMPORT_SWIFTTLS && canImport(SwiftTLS)
#if EXPORT_SWIFTTLS
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS
#else
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) @_weakLinked internal import SwiftTLS
#endif
#endif

/// Which implementation runs a `QUICConnection`.
@available(Network 0.1.0, *)
enum QUICConnectionDriver: Equatable {
    /// `QUICConnectionCore` if it supports the connection's options, the classes otherwise.
    case automatic
    /// `QUICConnectionCore`.
    case core
    /// The classes of `QUICConnection` itself: recovery, ack, pending items and the rest.
    case legacy

    /// `SWIFTNETWORK_QUIC_DRIVER=legacy` runs every connection on the classes, to compare the two.
    static let environmentOverride: QUICConnectionDriver? = {
        guard let value = getenv("SWIFTNETWORK_QUIC_DRIVER") else { return nil }
        switch String(cString: value) {
        case "legacy": return .legacy
        case "core": return .core
        default: return nil
        }
    }()
}

/// Holds the core of a connection, which can't be stored as an optional and still be borrowed.
@available(Network 0.1.0, *)
final class QUICConnectionCoreBox {
    var core: QUICConnectionCore
    /// The deadline the timer is armed for.
    var armedDeadline: NetworkClock.Instant?

    init(_ core: consuming QUICConnectionCore) {
        self.core = core
    }
}

// MARK: - Choosing the driver

@available(Network 0.1.0, *)
extension QUICConnection {
    /// Whether `QUICConnectionCore` implements everything the options ask for.
    static func coreSupports(
        _ options: QUICConnectionProtocol.QUICConnectionOptions,
        tlsOptions: SwiftTLSProtocol.Options?,
        isServer: Bool
    ) -> Bool {
        if options.retry || options.forceVersionNegotiation || options.forceUnsupportedClientVersion
            || options.testSendingShortPackets || options.enablePacing || options.enableL4S == true
            // The application announces and retires the connection IDs itself.
            || options.disableAutomaticNewConnectionIDs
        {
            return false
        }
        #if QlogOutput
        if options.qlogConfiguration != nil {
            return false
        }
        #endif
        if let tlsOptions {
            if tlsOptions.enableEarlyData {
                return false
            }
            #if EXPORT_SWIFTTLS
            if tlsOptions.tlsOptions.asyncVerifier != nil {
                return false
            }
            #endif
        }
        return true
    }

    func chooseDriver(
        _ options: QUICConnectionProtocol.QUICConnectionOptions,
        tlsOptions: SwiftTLSProtocol.Options?
    ) -> Bool {
        switch QUICConnectionDriver.environmentOverride ?? options.driver {
        case .legacy:
            return false
        case .core:
            return true
        case .automatic:
            return Self.coreSupports(options, tlsOptions: tlsOptions, isServer: self.isServer)
        }
    }

    /// The configuration of the core, from the options as `setupLocalTransportParameters` reads them.
    func makeCoreConfiguration(
        quicOptions: ProtocolOptions<QUICProtocol>,
        tlsOptions: SwiftTLSProtocol.Options
    ) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: tlsOptions)
        let connectionOptions = quicOptions.connectionOptions
        configuration.initialMaxData =
            connectionOptions.initialMaxData == .max
            ? UInt64(FlowControlGlobals.shared.initialMaxData) : connectionOptions.initialMaxData
        configuration.initialMaxStreamDataBidirectionalLocal =
            connectionOptions.initialMaxStreamDataBidirectionalLocal == .max
            ? UInt64(FlowControlGlobals.shared.initialMaxBidirectionalStreamLocalData)
            : connectionOptions.initialMaxStreamDataBidirectionalLocal
        configuration.initialMaxStreamDataBidirectionalRemote =
            connectionOptions.initialMaxStreamDataBidirectionalRemote == .max
            ? UInt64(FlowControlGlobals.shared.initialMaxBidirectionalStreamRemoteData)
            : connectionOptions.initialMaxStreamDataBidirectionalRemote
        configuration.initialMaxStreamDataUnidirectional =
            connectionOptions.initialMaxStreamDataUnidirectional == .max
            ? UInt64(FlowControlGlobals.shared.initialMaxUnidirectionalStreamData)
            : connectionOptions.initialMaxStreamDataUnidirectional
        configuration.initialMaxStreamsBidirectional =
            connectionOptions.initialMaxStreamsBidirectional == .max
            ? UInt64(FlowControlGlobals.shared.maxConcurrentStreams) : connectionOptions.initialMaxStreamsBidirectional
        configuration.initialMaxStreamsUnidirectional =
            connectionOptions.initialMaxStreamsUnidirectional == .max
            ? UInt64(FlowControlGlobals.shared.maxConcurrentStreams)
            : connectionOptions.initialMaxStreamsUnidirectional
        if let perProtocolOptions = quicOptions.perProtocolOptions {
            let options = perProtocolOptions.quicConnectionOptions
            configuration.maxIdleTimeout = options.idleTimeout
            configuration.maxUnacknowledgedKeepAlives = Int(options.keepaliveCount)
            configuration.maxUDPPayloadSize = UInt64(
                min(
                    max(Int(options.maxUDPPayloadSize), Int(TransportParameters.minUDPPayloadSize)),
                    Int(TransportParameters.maxUDPPayloadSize)
                )
            )
            if options.maxDatagramFrameSize > 0 {
                configuration.maxDatagramFrameSize = UInt64(
                    min(options.maxDatagramFrameSize, UInt16(TransportParameters.maxDatagramFrameSize))
                )
            }
        }
        configuration.maxDatagramSize = self.initialMSS
        configuration.initialDatagramSize = self.initialMSS
        configuration.activeConnectionIDLimit = Constants.activeCIDLimit
        return configuration
    }
}

// MARK: - Driving the core

@available(Network 0.1.0, *)
extension QUICConnection {
    /// Starts a client's handshake, or prepares a server for the client's first packet.
    func coreConnect(
        scid: QUICConnectionID,
        statelessResetToken: QUICStatelessResetToken,
        in eventContext: inout NetworkContext.EventContext
    ) {
        self.coreStatelessResetToken = statelessResetToken
        if self.coreTimerID == nil {
            self.coreTimerID = self.timer.insert(description: "Core", timerNow: self.now, in: &eventContext) {
                firedAt,
                timerState in
                self.coreTimerFired(at: firedAt, in: &timerState)
            }
        }
        guard !self.isServer, self.state == .idle, self.coreBox == nil else { return }
        guard var configuration = self.coreConfiguration else {
            self.log.error("Client failed to start: no TLS options")
            self.deliverDisconnectedEvent(flow: .allFlows, error: NetworkError.posix(EINVAL), in: &eventContext)
            return
        }
        configuration.statelessResetToken = nil
        self.handshakeStartTime = self.now
        let core = QUICConnectionCore(
            clientWith: configuration,
            localConnectionID: scid,
            destinationConnectionID: self.originalDCID,
            now: self.now
        )
        self.coreBox = QUICConnectionCoreBox(core)
        if self.keepaliveDuration != .zero {
            self.coreBox?.core.setKeepAliveInterval(self.keepaliveDuration, now: self.now)
        }
        self.state.change(to: .initialSent, logIDString: self.logPrefixer.logIDString)
        self.coreAfterUpdate(in: &eventContext)
    }

    /// Creates the server's core for the client's first Initial packet. Returns `false` if the
    /// datagram doesn't start a connection.
    private func coreAcceptFirstDatagram(
        _ datagram: RawSpan,
        on path: QUICPath,
        in eventContext: inout NetworkContext.EventContext
    ) -> Bool {
        var reader = CoreReader(datagram)
        guard let first = reader.uint8(), first & 0x80 != 0, let version = reader.uint32(),
            let destinationLength = reader.uint8(), destinationLength <= 20,
            let destination = reader.array(Int(destinationLength)),
            let sourceLength = reader.uint8(), sourceLength <= 20,
            let source = reader.array(Int(sourceLength)),
            let destinationConnectionID = QUICConnectionID(destination),
            let sourceConnectionID = QUICConnectionID(source)
        else {
            self.log.datapath("Unable to parse a packet from the frame")
            return false
        }
        guard version == QUICVersion.v1.rawValue else {
            // A long header with a version we don't speak gets a Version Negotiation packet.
            self.negotiatedVersion = self.initialVersion
            self.sendVersionNegotiation(
                destinationConnectionID: sourceConnectionID,
                sourceConnectionID: destinationConnectionID,
                path: path,
                in: &eventContext
            )
            if self.state != .versionSent {
                self.state.change(to: .versionSent, logIDString: self.logPrefixer.logIDString)
            }
            return false
        }
        // Only an Initial packet in a datagram of at least 1200 bytes starts a connection
        // (RFC 9000 Section 14.1).
        guard (first >> 4) & 0x03 == 0x00, datagram.byteCount >= Constants.initialMSS, destinationLength >= 8 else {
            self.log.error("First packet from the client is not a full-size Initial")
            return false
        }
        guard var configuration = self.coreConfiguration, let scid = path.scid else {
            self.log.error("Server failed to start: no TLS options")
            return false
        }
        configuration.statelessResetToken = self.coreStatelessResetToken
        configuration.disableActiveMigration = self.localCIDLength == 0
        self.originalDCID = destinationConnectionID
        if self.initialDCID == nil {
            self.initialDCID = destinationConnectionID
        }
        self.negotiatedVersion = .v1
        self.handshakeStartTime = self.now
        let core = QUICConnectionCore(
            serverWith: configuration,
            localConnectionID: scid,
            originalDestinationConnectionID: destinationConnectionID,
            peerConnectionID: sourceConnectionID,
            now: self.now
        )
        self.coreBox = QUICConnectionCoreBox(core)
        if self.keepaliveDuration != .zero {
            self.coreBox?.core.setKeepAliveInterval(self.keepaliveDuration, now: self.now)
        }
        path.assignDCID(sourceConnectionID, in: &eventContext)
        self.state.change(to: .initialReceived, logIDString: self.logPrefixer.logIDString)
        self.keyState = .handshake
        return true
    }

    func coreServiceReceivedDatagrams(
        path pathID: MultiplexingPathIdentifier,
        in eventContext: inout NetworkContext.EventContext
    ) {
        self.withPinnedClock {
            var datagrams = FrameArray()
            var path: QUICPath?
            self.accessReceivedDatagrams(path: pathID) { received, receivingPath in
                swap(&datagrams, &received)
                path = receivingPath
            }
            guard let path else {
                datagrams.finalizeAllFramesAsFailed()
                return
            }
            if self.coreReportedClose && self.coreBox == nil {
                // Closed for good. Until then, the core answers with CONNECTION_CLOSE.
                datagrams.finalizeAllFramesAsFailed()
                return
            }
            var receivedBytes = 0
            let receivedPackets = datagrams.count
            let now = self.now
            datagrams.iterateMutableFrames { frame in
                receivedBytes &+= frame.unclaimedLength
                if self.coreBox == nil {
                    guard self.isServer,
                        frame.withUnclaimedBytes({ self.coreAcceptFirstDatagram($0, on: path, in: &eventContext) })
                            == true
                    else {
                        frame.finalize(success: true)
                        return .removeFrameAndContinue
                    }
                }
                if let box = self.coreBox {
                    _ = frame.withUnclaimedMutableSpan { span in
                        box.core.receive(&span, now: now)
                    }
                }
                frame.finalize(success: true)
                return .removeFrameAndContinue
            }
            self.recordRxPackets(
                totalRxBytes: receivedBytes,
                totalPackets: receivedPackets,
                pathStatistics: &path.pathStatistics,
                connectionStatistics: &self.stats
            )
            self.lastPacketReceivedTimestamp = now
            if let box = self.coreBox, !self.isServer, box.core.peerConnectionID != path.dcid {
                // The server picked its connection ID.
                path.assignDCID(box.core.peerConnectionID, in: &eventContext)
            }
            self.coreAfterUpdate(in: &eventContext)
        }
    }

    /// Acts on the core's events, opens pending streams, sends, and re-arms the timer.
    func coreAfterUpdate(in eventContext: inout NetworkContext.EventContext) {
        guard self.coreBox != nil else { return }
        if self.coreIsUpdating {
            self.coreUpdatePending = true
            return
        }
        self.coreIsUpdating = true
        defer { self.coreIsUpdating = false }
        repeat {
            self.coreUpdatePending = false
            self.coreProcessEvents(in: &eventContext)
            self.coreOpenPendingStreams(in: &eventContext)
            if !self.pendOutboundData || self.coreBox?.core.isTerminating == true {
                self.coreSendDatagrams(in: &eventContext)
            }
            // Report a close only once its CONNECTION_CLOSE is on the way, as the application may
            // tear the path down when it hears about it.
            if let box = self.coreBox, box.core.isTerminating, !self.coreReportedClose,
                let reason = box.core.closeReason
            {
                self.coreReportClose(reason, in: &eventContext)
            }
        } while self.coreUpdatePending
        self.coreRescheduleTimer(in: &eventContext)
        self.checkConnectionIdle(unackedPacketCount: 0, in: &eventContext)
    }

    private func coreProcessEvents(in eventContext: inout NetworkContext.EventContext) {
        while let box = self.coreBox, let event = box.core.nextEvent() {
            switch event {
            case .connected:
                self.coreConnected(in: &eventContext)
            case .streamOpened(let id):
                self.coreCreateInboundStream(id, in: &eventContext)
            case .streamReadable(let id):
                if let stream = self.coreFlow(forStream: id) {
                    self.coreDeliverReadableData(stream, in: &eventContext)
                }
            case .streamWritable:
                // The core buffers every write, so the application never waits for room.
                break
            case .streamReset(let id, let errorCode):
                if let stream = self.coreFlow(forStream: id) {
                    self.corePeerResetStream(stream, errorCode: errorCode, in: &eventContext)
                }
            case .stopSending(let id, let errorCode):
                if let stream = self.coreFlow(forStream: id) {
                    self.corePeerStoppedSending(stream, errorCode: errorCode, in: &eventContext)
                }
            case .streamFinishedSending(let id):
                if let stream = self.coreFlow(forStream: id) {
                    stream.peerAcknowledgedFIN = true
                    stream.send.state = .dataReceived
                }
            case .streamClosed(let id):
                if let stream = self.coreFlow(forStream: id) {
                    stream.coreStreamClosed = true
                    self.coreCloseStreamIfDone(stream, in: &eventContext)
                }
            case .datagramsReadable:
                self.coreDeliverDatagrams(in: &eventContext)
            case .closed(let reason):
                self.coreReportClose(reason, in: &eventContext)
                self.coreFinish(in: &eventContext)
                return
            }
        }
    }

    private func coreFlow(forStream id: UInt64) -> QUICStreamInstance? {
        guard let streamID = QUICStreamID(id), let flowID = self.knownFlows[streamID] else { return nil }
        return self.flow(for: flowID)
    }

    // MARK: Output

    private func coreSendDatagrams(in eventContext: inout NetworkContext.EventContext) {
        guard let box = self.coreBox, var path = self.currentPath else { return }
        let datagramSize = max(path.mss, Constants.initialMSS)
        var totalBytes = 0
        var totalPackets = 0
        let now = self.now
        while true {
            guard
                var datagrams = try? self.getDatagramsToSend(
                    path: path.pathIdentifier,
                    maximumDatagramCount: 1,
                    minimumDatagramSize: datagramSize,
                    in: &eventContext
                ),
                var datagram = datagrams.popFirst()
            else {
                // `handleOutboundRoomAvailableEvent` sends again.
                break
            }
            let written =
                datagram.withUnclaimedMutableSpan { span in
                    box.core.send(into: &span, now: now)
                } ?? nil
            guard let written, written > 0, datagram.collapse(to: written) else {
                datagram.finalize(success: false)
                break
            }
            QUICSignpost.outbound(id: self.signpostID, length: written)
            totalBytes &+= written
            totalPackets &+= 1
            path.enqueueOutboundDatagram(datagram)
        }
        guard totalPackets > 0 else { return }
        self.recordTxPackets(
            totalTxBytes: totalBytes,
            totalPackets: totalPackets,
            pathStatistics: &path.pathStatistics,
            connectionStatistics: &self.stats
        )
        path.serviceLowerSendQueue(in: &eventContext)
    }

    // MARK: Timer

    private func coreRescheduleTimer(in eventContext: inout NetworkContext.EventContext) {
        guard let box = self.coreBox, let timerID = self.coreTimerID else { return }
        guard let deadline = box.core.nextDeadline else {
            if box.armedDeadline != nil {
                box.armedDeadline = nil
                self.timer.reschedule(identifier: timerID, fromNow: .zero, timerNow: self.now, in: &eventContext)
            }
            return
        }
        guard box.armedDeadline != deadline else { return }
        box.armedDeadline = deadline
        let now = self.now
        // Zero disarms the timer, so a deadline that already passed fires as soon as possible.
        let delay = deadline > now ? now.duration(to: deadline) : .microseconds(1)
        self.timer.reschedule(identifier: timerID, fromNow: delay, timerNow: now, in: &eventContext)
    }

    private func coreTimerFired(at firedAt: NetworkClock.Instant, in eventContext: inout NetworkContext.EventContext) {
        guard let box = self.coreBox else { return }
        // The timer runs entries up to its threshold early; they count as on time.
        let now = max(firedAt, box.armedDeadline ?? firedAt)
        box.armedDeadline = nil
        box.core.handleTimeout(now: now)
        self.coreAfterUpdate(in: &eventContext)
    }

    // MARK: Handshake

    private func coreConnected(in eventContext: inout NetworkContext.EventContext) {
        guard let box = self.coreBox else { return }
        self.negotiatedVersion = .v1
        self.state.change(to: .connected, logIDString: self.logPrefixer.logIDString)
        if let signpostConnectInterval {
            QUICSignpost.connectEnd(signpostConnectInterval)
        }
        self.handshakeDuration = self.handshakeStartTime.duration(to: self.now)
        self.keyState = .phase0
        self.initialKeysDiscarded = true
        self.isHandshakeConfirmed = box.core.isHandshakeConfirmed || self.isServer
        let peerParameters = box.core.peerTransportParameters
        self.connectionMetadata.activeConnectionIDLimit = peerParameters?.intValue(.activeConnectionIDLimit) ?? 2
        self.remoteMaxDatagramFrameSize = min(
            box.core.peerMaxDatagramFrameSize,
            Int(TransportParameters.maxDatagramFrameSize)
        )
        self.connectionMetadata.remoteMaxDatagramFrameSize = UInt16(truncatingIfNeeded: self.remoteMaxDatagramFrameSize)
        // Flows opened before the peer's limit was known sized themselves against zero.
        self.applyToAllSecondaryFlows { self.coreUpdateUsableDatagramSize($0) }
        if peerParameters?[.disableActiveMigration] == nil {
            self.migrationSupported = true
        }
        self.log.notice("QUIC connection established in \(self.handshakeDuration)")

        // Streams opened before the handshake completed get their IDs now.
        self.coreOpenPendingStreams(in: &eventContext)
        self.deliverConnectedEvent(flow: .allFlows, in: &eventContext)
        self.stats.increment(.connectionAttempts)
    }

    // MARK: Closing

    /// Closes the connection, from `close(sendCloseFrame:in:)`.
    func coreClose(in eventContext: inout NetworkContext.EventContext) {
        guard !self.coreReportedClose else { return }
        guard let box = self.coreBox else {
            // Nothing was sent or received yet.
            self.coreReportClose(.local(errorCode: 0, isApplication: false), in: &eventContext)
            self.coreFinish(in: &eventContext)
            return
        }
        let errorCode: UInt64
        let isApplication: Bool
        let reason: String
        if let applicationCloseError {
            errorCode = UInt64(clamping: applicationCloseError.code)
            isApplication = true
            reason = applicationCloseError.reason ?? ""
        } else if let closeError {
            errorCode = UInt64(clamping: closeError.code)
            isApplication = false
            reason = closeError.reason ?? ""
        } else {
            errorCode = 0
            isApplication = false
            reason = ""
        }
        box.core.close(errorCode: errorCode, isApplication: isApplication, reason: reason, now: self.now)
        // Sends the CONNECTION_CLOSE, then reports the close.
        self.coreAfterUpdate(in: &eventContext)
    }

    /// Tells the application the connection is gone, as `close(sendCloseFrame:in:)` does.
    private func coreReportClose(
        _ reason: QUICConnectionCore.CloseReason,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard !self.coreReportedClose else { return }
        self.coreReportedClose = true
        let wasConnected = self.state == .connected
        switch reason {
        case .local:
            break
        case .peer(let errorCode, let isApplication, let reason):
            if errorCode != 0 {
                if isApplication {
                    self.applicationCloseError = QUICApplicationError(Int64(clamping: errorCode), reason)
                    self.receivedApplicationClose = true
                } else {
                    self.closeError = QUICTransportError(errorCode, reason)
                    self.receivedConnectionClose = true
                }
            }
            self.log.info("Received CONNECTION_CLOSE code: \(errorCode), reason: '\(reason)'")
        case .idleTimeout:
            self.errorToReport = NetworkError.posix(ETIMEDOUT)
            self.log.info("Idle timeout fired, closing connection due to inactivity")
        case .keepAliveTimeout:
            self.closeError = QUICTransportError(.noError, "keepalive limit reached")
            self.errorToReport = NetworkError.posix(ETIMEDOUT)
        case .statelessReset:
            self.stats.increment(.statelessResetReceived)
            self.log.info("Received valid stateless reset token")
            self.errorToReport = NetworkError.posix(ECONNRESET)
        case .transportError(let errorCode, let reason):
            if self.closeError == nil {
                self.closeError =
                    QUICTransportError(errorCode, reason) ?? QUICTransportError(.internalError, reason)
            }
        }
        QUICSignpost.disconnect(id: self.signpostID)
        if self.errorToReport == nil && (!wasConnected || self.receivedConnectionClose || self.receivedApplicationClose)
        {
            if let applicationCloseError {
                self.errorToReport = NetworkError(quicApplicationError: applicationCloseError)
            } else if let closeError {
                self.errorToReport = NetworkError(quicTransportError: closeError)
            }
        }
        if self.state != .idle && self.state != .invalid && !self.state.isTerminal {
            self.state.change(to: .closing, logIDString: self.logPrefixer.logIDString)
        }
        self.knownFlows.removeAll()
        let retiredMetadata = self.connectionMetadata
        self.connectionMetadata = .init()
        self.deliverDisconnectedEvent(flow: .allFlows, error: self.errorToReport, in: &eventContext)
        self.unsetMetadataHandlers()
        self.unsetMetadataHandlers(on: retiredMetadata)
    }

    /// Releases the core once it is closed.
    private func coreFinish(in eventContext: inout NetworkContext.EventContext) {
        if self.state == .closing {
            self.state.change(to: .draining, logIDString: self.logPrefixer.logIDString)
        }
        self.timer.stop(in: &eventContext)
        self.coreTimerID = nil
        self.coreBox = nil
        self.currentPath = nil
    }

    // MARK: Streams

    /// Lets the peer open more streams, from the connection metadata or an application event.
    func coreRaiseLocalMaxStreams(
        _ maximumStreams: Int,
        bidirectional: Bool,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let box = self.coreBox else { return }
        guard UInt64(clamping: maximumStreams) <= Constants.maxStreamLimit else {
            self.log.error("Received MAX_STREAMS value too large: \(maximumStreams)")
            self.closeError = QUICTransportError(.streamLimitError, "MAX_STREAMS value over limit")
            self.close(in: &eventContext)
            return
        }
        self.log.notice("Advertising MAX_STREAMS \(bidirectional ? "bidi" : "uni"): \(maximumStreams)")
        box.core.raiseLocalMaxStreams(to: UInt64(clamping: maximumStreams), bidirectional: bidirectional)
        self.coreAfterUpdate(in: &eventContext)
    }

    /// Sets up a stream the application opened, from `setupNewOutboundStream`.
    func coreSetupNewOutboundStream(_ stream: QUICStreamInstance, with protocolOptions: QUICStreamProtocol.Options) {
        let isUnidirectional = protocolOptions.isUnidirectional
        let flowID = stream.flowIdentifier
        stream.streamMetadata.quicConnectionMetadata = self.connectionMetadata
        stream.setup(streamID: nil, logPrefixer: self.logPrefixer)
        stream.unidirectional = isUnidirectional
        if isUnidirectional {
            self.stats.increment(.outboundUnidirectionalStreams)
        } else {
            self.stats.increment(.outboundBidirectionalStreams)
        }
        // A stream opened while connected is ready right away, and `connect(flow:)` reports it.
        // Otherwise it waits for the handshake, or for the peer to allow more streams.
        if self.state == .connected, let box = self.coreBox, !box.core.isTerminating,
            self.pendingStreams(unidirectional: isUnidirectional).isEmpty,
            let id = box.core.openStream(bidirectional: !isUnidirectional), let streamID = QUICStreamID(id)
        {
            self.coreAssign(streamID, to: stream)
        } else {
            self.withMutableQUICStreams(unidirectional: isUnidirectional) { $0.addPending(stream) }
        }
        // `setup(flow:)` runs on the attach path, which deliberately does not carry the context
        // state, so this is a genuine entry point into the stack.
        self.fromExternal { eventContext in
            self.serviceStreamDataToSend(flow: flowID, in: &eventContext)
        }
    }

    private func pendingStreams(unidirectional: Bool) -> [QUICStreamInstance] {
        unidirectional ? self.unidirectionalStreams.pendingStartStreams : self.bidirectionalStreams.pendingStartStreams
    }

    private func coreAssign(_ streamID: QUICStreamID, to stream: QUICStreamInstance) {
        stream.resetStreamID(streamID: streamID)
        self.knownFlows[streamID] = stream.flowIdentifier
        stream.outboundStreamReady()
        self.withMutableQUICStreams(unidirectional: stream.unidirectional) { $0.incrementActiveStreams() }
    }

    /// Gives pending streams their IDs while the peer's stream limits allow it, oldest first.
    private func coreOpenPendingStreams(in eventContext: inout NetworkContext.EventContext) {
        guard self.state == .connected, let box = self.coreBox, !box.core.isTerminating else { return }
        for unidirectional in [false, true] {
            while let stream = self.pendingStreams(unidirectional: unidirectional).first {
                guard let id = box.core.openStream(bidirectional: !unidirectional), let streamID = QUICStreamID(id)
                else {
                    break
                }
                self.withMutableQUICStreams(unidirectional: unidirectional) { $0.removePending(stream) }
                self.coreAssign(streamID, to: stream)
                self.deliverConnectedEvent(flow: stream.flowIdentifier, in: &eventContext)
                self.coreWriteQueuedStreamData(stream, in: &eventContext)
            }
        }
    }

    private func coreCreateInboundStream(_ id: UInt64, in eventContext: inout NetworkContext.EventContext) {
        guard let box = self.coreBox, let streamID = QUICStreamID(id) else { return }
        guard !self.inboundFlowLinkage.isDetached else {
            self.log.error("No inbound flow handler, cannot accept stream ID \(streamID)")
            // Tell the peer we refuse the stream.
            box.core.stopSending(id, errorCode: 0)
            if streamID.isBidirectional {
                box.core.resetStream(id, errorCode: 0)
            }
            return
        }
        let newStream = QUICStreamInstance(parent: self, inbound: true, in: &eventContext)
        newStream.streamMetadata.quicConnectionMetadata = self.connectionMetadata
        let newFlowIdentifier = newStream.flowIdentifier
        self.multiplexedFlows[newFlowIdentifier] = newStream
        self.knownFlows[streamID] = newFlowIdentifier
        newStream.setup(streamID: streamID, logPrefixer: self.logPrefixer)
        newStream.unidirectional = streamID.isUnidirectional
        let abstractMetadata: AbstractProtocolMetadata = ProtocolMetadata<QUICStreamProtocol>(
            protocolIdentifier: QUICStreamProtocol.identifier,
            perProtocolMetadata: newStream.streamMetadata,
            messageIdentifier: SystemUUID(insecure: true)
        )
        self.deliverNewInboundFlowEvent(newStream.identifier, flowMetadata: abstractMetadata, in: &eventContext)
        newStream.inboundStreamReady()
        if streamID.isBidirectional {
            self.stats.increment(.inboundBidirectionalStreams)
        } else {
            self.stats.increment(.inboundUnidirectionalStreams)
        }
        self.log.info("Creating inbound stream \(streamID)")
    }

    /// Moves the application's writes into the core, from `serviceStreamDataToSend`.
    func coreServiceStreamDataToSend(_ stream: QUICStreamInstance, in eventContext: inout NetworkContext.EventContext) {
        self.withPinnedClock {
            self.coreWriteQueuedStreamData(stream, in: &eventContext)
            self.checkConnectionIdle(unackedPacketCount: 0, in: &eventContext)
            self.coreAfterUpdate(in: &eventContext)
        }
    }

    private func coreWriteQueuedStreamData(
        _ stream: QUICStreamInstance,
        in eventContext: inout NetworkContext.EventContext
    ) {
        // A pending stream keeps its data until it has an ID.
        guard let streamID = stream.streamID, let box = self.coreBox else { return }
        let id = streamID.value
        var finish = false
        self.accessStreamDataToSend(stream: stream) { streamData in
            while var frame = streamData.popFirst() {
                // If the connection is complete, it is always a FIN.
                var isFinal = frame.connectionComplete
                if frame.protocolMetadatas.count > 0,
                    frame.protocolMetadatas[0].metadata.matches(protocolIdentifier: QUICConnectionProtocol.identifier)
                {
                    isFinal = isFinal || frame.metadataComplete
                }
                if frame.unclaimedLength > 0 {
                    _ = frame.withUnclaimedBytes { bytes in
                        box.core.write(bytes, to: id)
                    }
                }
                frame.finalize(success: true)
                if isFinal {
                    finish = true
                    break
                }
            }
        }
        if finish {
            self.disconnect(flow: stream.flowIdentifier, direction: .outbound, in: &eventContext)
        }
    }

    /// Delivers what the core has to read on `stream`, once the application took what it got
    /// before.
    func coreDeliverReadableData(_ stream: QUICStreamInstance, in eventContext: inout NetworkContext.EventContext) {
        guard let box = self.coreBox, let streamID = stream.streamID, !stream.readClosed,
            !stream.markedInboundFINOnFrame, stream.upperReceiveQueue.isEmpty
        else {
            return
        }
        var frames = FrameArray()
        var fin = false
        var length = 0
        _ = box.core.read(from: streamID.value) { bytes, isFinished in
            length = bytes.byteCount
            fin = isFinished
            guard length > 0 || isFinished else { return (0, ()) }
            var frame = bytes.withUnsafeBytes { Frame(copyBuffer: $0) }
            if isFinished {
                frame.metadataComplete = true
                frame.connectionComplete = true
            }
            frames.add(frame: frame)
            return (length, ())
        }
        guard length > 0 || fin else {
            frames.finalizeAllFramesAsFailed()
            return
        }
        if fin {
            stream.markedInboundFINOnFrame = true
        }
        var flow = stream
        try? self.deliverInboundStreamData(flow: &flow, streamData: frames, in: &eventContext)
    }

    /// The application read from `stream`, from `upperReceiveQueueDrainedBytes`.
    func coreStreamDrained(_ stream: QUICStreamInstance, in eventContext: inout NetworkContext.EventContext) {
        guard stream.upperReceiveQueue.isEmpty else { return }
        if stream.markedInboundFINOnFrame {
            if stream.receive.state != .dataRead {
                stream.receive.state.change(logIDString: stream.log.logPrefix, to: .dataRead)
            }
            self.coreCloseStreamIfDone(stream, in: &eventContext)
        } else {
            self.coreDeliverReadableData(stream, in: &eventContext)
        }
        self.coreAfterUpdate(in: &eventContext)
    }

    /// Closes the flow of a stream the core is done with, once the application read everything.
    private func coreCloseStreamIfDone(_ stream: QUICStreamInstance, in eventContext: inout NetworkContext.EventContext)
    {
        guard !stream.closed else { return }
        let readDone =
            stream.unidirectional && stream.streamID?.isSendOnly(server: self.isServer) == true
            || stream.readClosed || (stream.markedInboundFINOnFrame && stream.upperReceiveQueue.isEmpty)
        if stream.coreStreamClosed && readDone {
            stream.close(errorCode: nil, in: &eventContext)
        } else if stream.peerAcknowledgedFIN && readDone {
            stream.close(errorCode: nil, in: &eventContext)
        }
    }

    private func corePeerResetStream(
        _ stream: QUICStreamInstance,
        errorCode: UInt64,
        in eventContext: inout NetworkContext.EventContext
    ) {
        stream.streamMetadata.applicationError = errorCode
        stream.inboundApplicationError = errorCode
        self.deliverInboundAbortedEvent(
            stream: stream,
            error: NetworkError(quicApplicationError: errorCode),
            in: &eventContext
        )
        stream.resetReceived = true
        stream.receive.state = .resetReceived
        stream.readClosed = true
        // A receiver of RESET_STREAM can discard any data that it already received on that stream.
        let isReceiveOnly = stream.streamID?.isReceiveOnly(server: self.isServer) ?? false
        if isReceiveOnly || stream.receivedStopSending || stream.writeClosed {
            stream.close(errorCode: NetworkError.posix(ECONNRESET), in: &eventContext)
        }
    }

    private func corePeerStoppedSending(
        _ stream: QUICStreamInstance,
        errorCode: UInt64,
        in eventContext: inout NetworkContext.EventContext
    ) {
        stream.receivedStopSending = true
        let streamError =
            stream.receive.state == .resetReceived ? NetworkError.posix(ECONNRESET) : NetworkError.posix(ENOTCONN)
        stream.streamMetadata.applicationError = errorCode
        stream.outboundApplicationError = errorCode
        stream.deliverOutboundAbortedEvent(error: NetworkError(quicApplicationError: errorCode), in: &eventContext)
        // The core answers with RESET_STREAM.
        stream.writeClosed = true
        let isSendOnly = stream.streamID?.isSendOnly(server: self.isServer) ?? false
        if isSendOnly || stream.receive.state == .resetReceived || stream.receive.state == .dataRead {
            stream.close(errorCode: streamError, in: &eventContext)
        }
    }

    /// The application stopped reading, from `handleStopRead`.
    func coreStopRead(_ stream: QUICStreamInstance) {
        if stream.pendingStart {
            self.withMutableQUICStreams(unidirectional: stream.unidirectional) { $0.removePending(stream) }
        }
        guard let box = self.coreBox, let streamID = stream.streamID, !self.coreReportedClose,
            !streamID.isSendOnly(server: self.isServer), !stream.markedInboundFINOnFrame, !stream.resetReceived
        else {
            stream.upperReceiveQueue.finalizeAllFramesAsFailed()
            return
        }
        box.core.stopSending(streamID.value, errorCode: stream.inboundApplicationError ?? 0)
        stream.stopSendRequested = true
        stream.upperReceiveQueue.finalizeAllFramesAsFailed()
    }

    /// The application stopped writing, from `handleStopWrite`. Returns whether the write side is
    /// closed.
    func coreStopWrite(_ stream: QUICStreamInstance) -> Bool {
        if stream.pendingStart {
            // The stream never got an ID, so the peer never heard of it.
            self.withMutableQUICStreams(unidirectional: stream.unidirectional) { $0.removePending(stream) }
            return true
        }
        guard let box = self.coreBox, let streamID = stream.streamID, !self.coreReportedClose,
            !streamID.isReceiveOnly(server: self.isServer), !stream.receivedStopSending
        else {
            return true
        }
        // The send state mirrors what the core does, for code that inspects it.
        if let code = stream.outboundApplicationError {
            box.core.resetStream(streamID.value, errorCode: code)
            stream.resetSent = true
            stream.send.state = .resetSent
        } else {
            box.core.finish(streamID.value)
            stream.send.state = .dataSent
        }
        return true
    }
}

// MARK: - Datagrams

@available(Network 0.1.0, *)
extension QUICConnection {
    /// The payload a datagram flow can send: what the core takes, less the flow ID in front.
    func coreUpdateUsableDatagramSize(_ flow: QUICDatagramFlow) {
        var usable = self.coreBox?.core.maxDatagramPayloadSize ?? 0
        if let flowID = flow.flowID {
            usable -= flowID.variableLengthSize
        }
        if let contextID = flow.contextID {
            usable -= contextID.variableLengthSize
        }
        flow.usableDatagramSize = max(0, usable)
    }

    /// Moves a flow's datagrams into the core, from `serviceDatagramsToSend`.
    func coreServiceDatagramsToSend(_ flow: QUICDatagramFlow, in eventContext: inout NetworkContext.EventContext) {
        guard let box = self.coreBox else { return }
        let flowID = flow.flowID
        let contextID = flow.contextID
        self.accessDatagramsToSend(flow: flow) { datagrams in
            while var datagram = datagrams.popFirst() {
                // The flow and context IDs go in front of the payload (RFC 9297 Section 2.1).
                var payload: [UInt8] = []
                payload.reserveCapacity(datagram.unclaimedLength &+ 16)
                if let flowID {
                    payload.appendVLE(flowID)
                }
                if let contextID {
                    payload.appendVLE(contextID)
                }
                _ = datagram.withUnclaimedBytes { bytes in
                    bytes.withUnsafeBytes { payload.append(contentsOf: $0) }
                }
                let accepted = box.core.sendDatagram(payload.span.bytes)
                if !accepted {
                    flow.log.error("Unable to send datagram of \(payload.count) bytes")
                }
                datagram.finalize(success: accepted)
            }
        }
        self.checkConnectionIdle(unackedPacketCount: 0, in: &eventContext)
        self.coreAfterUpdate(in: &eventContext)
    }

    /// Hands the datagrams the core received to their flows, opening a flow for an unknown ID.
    private func coreDeliverDatagrams(in eventContext: inout NetworkContext.EventContext) {
        guard let box = self.coreBox else { return }
        let useFlowID = self.datagramEnableFlowID
        let useContextID = self.datagramUseContextID
        // The payload is copied out first: delivering it may reach the core again.
        while let payload = box.core.readDatagram({ [UInt8](copying: $0) }) {
            var reader = CoreReader(payload.span.bytes)
            var flowID: UInt64?
            var contextID: UInt64?
            if useFlowID {
                flowID = reader.vle()
            }
            if useContextID {
                contextID = reader.vle()
            }
            guard (flowID != nil || !useFlowID) && (contextID != nil || !useContextID) else {
                self.log.error("Dropping a datagram without its flow or context ID")
                continue
            }
            let offset = reader.offset
            var frame = payload.span.bytes.extracting(offset..<payload.count).withUnsafeBytes {
                Frame(copyBuffer: $0)
            }
            frame.metadataComplete = true
            var matchingFlowIdentifier = self.findSecondaryFlow { candidate in
                candidate.contextID == contextID && candidate.flowID == flowID
            }
            if matchingFlowIdentifier == nil {
                guard !self.secondaryInboundFlowLinkage.isDetached else {
                    self.log.error("No secondary inbound flow handler, cannot accept datagram flow")
                    frame.finalize(success: false)
                    continue
                }
                let newFlow = QUICDatagramFlow(parent: self, inbound: true, in: &eventContext)
                newFlow.setup(datagramFlowID: flowID, contextID: contextID, logPrefixer: self.logPrefixer)
                self.multiplexedSecondaryFlows[newFlow.flowIdentifier] = newFlow
                self.coreUpdateUsableDatagramSize(newFlow)
                let datagramMetadata = QUICProtocol.metadata()
                datagramMetadata.perProtocolMetadata?.datagramFlowID = newFlow.flowID
                datagramMetadata.perProtocolMetadata?.isDatagramFlow = true
                datagramMetadata.perProtocolMetadata?.usableDatagramFrameSize = UInt16(newFlow.usableDatagramSize)
                datagramMetadata.perProtocolMetadata?.quicConnectionMetadata = self.connectionMetadata
                self.secondaryInboundFlowLinkage.deliverNewInboundFlowEvent(
                    flowInstance: newFlow.identifier,
                    flowMetadata: datagramMetadata,
                    from: self.identifier,
                    in: &eventContext
                )
                matchingFlowIdentifier = newFlow.flowIdentifier
            }
            guard let matchingFlowIdentifier else {
                frame.finalize(success: false)
                continue
            }
            try? self.deliverInboundDatagrams(
                flow: matchingFlowIdentifier,
                datagrams: .init(frame: frame),
                in: &eventContext
            )
        }
    }
}

@available(Network 0.1.0, *)
extension [UInt8] {
    /// Appends a variable-length integer (RFC 9000 Section 16) in its shortest encoding.
    fileprivate mutating func appendVLE(_ value: UInt64) {
        let length = CoreWriter.vleLength(value)
        let prefix: UInt64
        switch length {
        case 1: prefix = 0x00
        case 2: prefix = 0x40
        case 4: prefix = 0x80
        default: prefix = 0xc0
        }
        let shift = UInt64(8 * (length &- 1))
        self.append(UInt8(truncatingIfNeeded: (prefix << shift | value) >> shift))
        var index = length &- 1
        while index > 0 {
            index &-= 1
            self.append(UInt8(truncatingIfNeeded: value >> UInt64(8 * index)))
        }
    }
}

#endif
