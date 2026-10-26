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

// MARK: QUIC StreamID state
// Keeps track of the QUICStreamID state for local and remote uni/bidi streams
@available(Network 0.1.0, *)
struct QUICStreamIDState: ~Copyable {
    let logContext: String
    let streamType: QUICStreamType
    var remoteMaxStreams: Int = 0
    var previousRemoteMaxStreams: Int = 0
    var localMaxStreams: Int = 0
    var allocatedStreamCount: Int = 0
    var largestOutboundStreamID: QUICStreamID?
    var nextInboundStreamID: QUICStreamID?
    var remoteMaxStreamID: QUICStreamID?
    var localMaxStreamID: QUICStreamID?
    private(set) var activeStreams: Int = 0
    private(set) var pendingStartStreams: [QUICStreamInstance] = []

    init(_ type: QUICStreamType) {
        self.streamType = type
        self.logContext = streamType == .unidirectional ? "unidirectional" : "bidirectional"
    }

    mutating func incrementActiveStreams() {
        activeStreams += 1
    }

    mutating func decrementActiveStreams() {
        activeStreams = activeStreams > 0 ? activeStreams - 1 : 0
    }

    func activeStreamsRemaining() -> Int {
        activeStreams
    }

    mutating func addPending(_ stream: QUICStreamInstance) {
        guard !stream.pendingStart else {
            stream.log.error("Stream is already marked pendingStart \(logContext)")
            return
        }
        // streamID's will be nil if pending so check by identifier
        guard !pendingStartStreams.contains(where: { $0.identifier == stream.identifier }) else {
            stream.log.error("Stream is already on pending list \(logContext)")
            return
        }
        pendingStartStreams.append(stream)
        stream.pendingStart = true
        let logContext = self.logContext
        stream.log.debug("Is pending \(logContext)")
    }

    mutating func removePending(_ stream: QUICStreamInstance) {
        guard stream.pendingStart else {
            stream.log.error("Stream is not marked pendingStart \(logContext)")
            return
        }
        guard let index = pendingStartStreams.firstIndex(where: { $0.identifier == stream.identifier })
        else {
            stream.log.error("Stream is not on pending list \(logContext)")
            return
        }
        pendingStartStreams.remove(at: index)
        stream.pendingStart = false
        let logContext = self.logContext
        stream.log.debug("Is no longer pending \(logContext)")
    }

    mutating func removeAllPending() {
        while !pendingStartStreams.isEmpty {
            let stream = pendingStartStreams.popLast()!
            guard stream.pendingStart else {
                stream.log.error(
                    "Stream is not marked pendingStart \(logContext)"
                )
                return
            }
            stream.pendingStart = false
        }
    }

    mutating func allocateNewOutboundStreamID(
        isServer: Bool,
        logIDString: String,
        isUnidirectional: Bool
    ) -> QUICStreamID? {
        let newStreamID = QUICStreamID.nextAvailableStreamID(
            allocatedStreamCount: allocatedStreamCount,
            remoteMaxStreams: remoteMaxStreams,
            remoteMaxStreamID: remoteMaxStreamID,
            server: isServer,
            logIDString: logIDString,
            isUnidirectional: isUnidirectional
        )
        guard let newStreamID else {
            return nil
        }

        let (newValue, overflow) = self.allocatedStreamCount.addingReportingOverflow(1)
        guard !overflow else {
            return nil
        }
        self.allocatedStreamCount = newValue

        self.largestOutboundStreamID = newStreamID
        #if !DisableDebugLogging
        let logContext = self.logContext
        Logger.proto.debug(
            "\(logIDString) \(logContext) allocated new stream ID \(newStreamID)"
        )
        #endif
        return newStreamID
    }

    func checkInboundStreamID(
        _ streamID: QUICStreamID,
        server isServer: Bool,
        connection: QUICConnection,
        in eventContext: inout NetworkContext.EventContext
    ) -> (valid: Bool, checkZombie: Bool) {

        guard let nextInboundStreamID else {
            connection.log.fault("nextInboundStreamID is invalid")
            connection.close(with: .internalError, "inconsistent next inbound stream ID", in: &eventContext)
            return (valid: false, checkZombie: false)
        }

        if streamID.isInitiatedBy(server: isServer) {
            // We're handling a new inbound stream, but it's not a Stream ID that
            // the peer should have opened. Check if it's a stream we already closed?
            if let largestOutboundStreamID = self.largestOutboundStreamID,
                streamID <= largestOutboundStreamID
            {
                connection.log.info(
                    "[S\(streamID)] already closed (last \(logContext) \(largestOutboundStreamID))"
                )
                return (valid: false, checkZombie: true)
            } else {
                connection.log.error(
                    "Peer is attempting to open an invalid stream (\(streamID)); our role is \(isServer ? "server" : "client") (last \(logContext) \(largestOutboundStreamID?.description ?? "nil"))"
                )
                connection.close(with: .streamStateError, "invalid stream ID", in: &eventContext)

                return (valid: false, checkZombie: false)
            }
        }

        if newStreamIDsAreBlocked(streamID) {
            connection.log.error(
                "Stream ID \(streamID) exceeded the maximum allowed"
            )
            connection.close(with: .streamLimitError, "exceeded maximum stream ID", in: &eventContext)

            return (valid: false, checkZombie: false)
        }

        // Check if the stream is already closed.  If we got here, it was
        // because the lookup failed.  Don't re-create streams that are
        // already closed.
        if streamID < nextInboundStreamID {
            connection.log.info(
                "Not recreating closed stream (next \(logContext) \(nextInboundStreamID))"
            )
            return (valid: false, checkZombie: true)
        }
        return (valid: true, checkZombie: false)
    }

    // Set window to a non-zero value to check if there are room for N more streamIDs
    func newStreamIDsAreBlocked(
        _ streamID: QUICStreamID,
        server: Bool = false,
        window: Int = 0
    ) -> Bool {
        if localMaxStreams == 0 {
            return true
        }

        let compareMaxStreamID: QUICStreamID
        if window == 0 {
            guard let localMaxStreamID else {
                // The local Max Stream ID is yet to be determined, so new IDs are blocked
                return true
            }
            compareMaxStreamID = localMaxStreamID
        } else {
            guard localMaxStreams > window else {
                // Local max streams is less than the entire window, so new IDs are blocked
                return true
            }

            let adjustedMaxStreams = localMaxStreams - window

            let adjustedMaxStreamID: QUICStreamID?
            if streamType == .unidirectional {
                adjustedMaxStreamID = QUICStreamID.computeRemoteMaxStreamIDUnidirectional(
                    server: server,
                    streams: UInt64(adjustedMaxStreams)
                )
            } else {
                adjustedMaxStreamID = QUICStreamID.computeRemoteMaxStreamIDBidirectional(
                    server: server,
                    streams: UInt64(adjustedMaxStreams)
                )
            }

            guard let adjustedMaxStreamID else {
                return true
            }
            compareMaxStreamID = adjustedMaxStreamID
        }

        if streamID >= compareMaxStreamID {
            return true
        }

        return false
    }

    mutating func resetStreamsState(
        nextInboundStreamID: QUICStreamID,
        largestOutboundStreamID: QUICStreamID
    ) {
        self.allocatedStreamCount = 0
        self.nextInboundStreamID = nextInboundStreamID
        if self.largestOutboundStreamID == nil {
            self.largestOutboundStreamID = largestOutboundStreamID
        }
    }

    mutating func updateRemoteMaxStreams(server: Bool, newMaxStreams: Int, logIDString: String) {
        remoteMaxStreams = newMaxStreams
        if streamType == .unidirectional {
            remoteMaxStreamID = QUICStreamID.computeRemoteMaxStreamIDUnidirectional(
                server: server,
                streams: UInt64(newMaxStreams)
            )
        } else {
            remoteMaxStreamID = QUICStreamID.computeRemoteMaxStreamIDBidirectional(
                server: server,
                streams: UInt64(newMaxStreams)
            )
        }
        #if !DisableDebugLogging
        let logContext = self.logContext
        let remoteMaxStreamID = self.remoteMaxStreamID
        Logger.proto.debug(
            "\(logIDString) \(logContext) Got newMaxStreams=\(newMaxStreams) which gives remoteMaxStreamID=\(remoteMaxStreamID?.description ?? "unknown")"
        )
        #endif
    }

    mutating func updateLocalMaxStreams(server: Bool, newMaxStreams: Int, logIDString: String) {
        localMaxStreams = newMaxStreams
        if streamType == .unidirectional {
            localMaxStreamID = QUICStreamID.computeRemoteMaxStreamIDUnidirectional(
                server: server,
                streams: UInt64(newMaxStreams)
            )
        } else {
            localMaxStreamID = QUICStreamID.computeRemoteMaxStreamIDBidirectional(
                server: server,
                streams: UInt64(newMaxStreams)
            )
        }
        #if !DisableDebugLogging
        let logContext = self.logContext
        let localMaxStreamID = self.localMaxStreamID
        Logger.proto.debug(
            "\(logIDString) \(logContext) Got newMaxStreams=\(newMaxStreams) which gives localMaxStreamID=\(localMaxStreamID?.description ?? "unknown")"
        )
        #endif
    }
}

// MARK: QUIC Stream

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public final class QUICStreamInstance: MultiplexedStreamFlow<QUICConnection, BaseInboundStreamLinkage>,
    UnidirectionalAbortingStreamFlow, EarlyDataStreamFlow
{
    /// The stream's protocol state; the class adds the framework flow around it.
    var state = QUICStreamProtocolState()

    typealias Flags = QUICStreamProtocolState.Flags

    private var flags: Flags {
        get { state.flags }
        set { state.flags = newValue }
    }

    var streamMetadata = QUICStreamProtocol.QUICStreamMetadata()

    /// Whether `QUICConnectionCore` is done with the stream: both directions finished.
    var coreStreamClosed: Bool {
        get { flags.contains(.coreStreamClosed) }
        set { if newValue { flags.insert(.coreStreamClosed) } else { flags.remove(.coreStreamClosed) } }
    }

    var receive: QUICReceiveState {
        _read { yield state.receive }
        _modify { yield &state.receive }
    }
    var send: QUICSendState {
        _read { yield state.send }
        _modify { yield &state.send }
    }

    @inline(always)
    var finalSize: UInt64? {
        get { state.finalSize }
        set { state.finalSize = newValue }
    }

    /// The application error code for the inbound (receive) direction.
    ///
    /// Used for the `STOP_SENDING` frame.
    @inline(always)
    var inboundApplicationError: UInt64? {
        get { state.inboundApplicationError }
        set { state.inboundApplicationError = newValue }
    }
    /// The application error code for the outbound (send) direction.
    ///
    /// Used for the `RESET_STREAM` frame.
    @inline(always)
    var outboundApplicationError: UInt64? {
        get { state.outboundApplicationError }
        set { state.outboundApplicationError = newValue }
    }
    @inline(always)
    private(set) var streamID: QUICStreamID? {
        get { state.streamID }
        set { state.streamID = newValue }
    }

    override public func asLowerLinkage() -> UpperProtocol.PairedLowerLinkage {
        BaseOutboundStreamLinkage(quicStream: self)
    }

    // Have sent DATA_BLOCKED for the stream without an increase
    var hasSentDataBlocked: Bool {
        get { flags.contains(.hasSentDataBlocked) }
        set {
            if newValue {
                flags.insert(.hasSentDataBlocked)
            } else {
                flags.remove(.hasSentDataBlocked)
            }
        }
    }
    fileprivate(set) var pendingStart: Bool {
        get { flags.contains(.pendingStart) }
        set { if newValue { flags.insert(.pendingStart) } else { flags.remove(.pendingStart) } }
    }
    var readClosed: Bool {
        get { flags.contains(.readClosed) }
        set { if newValue { flags.insert(.readClosed) } else { flags.remove(.readClosed) } }
    }
    var writeClosed: Bool {
        get { flags.contains(.writeClosed) }
        set { if newValue { flags.insert(.writeClosed) } else { flags.remove(.writeClosed) } }
    }
    var closed: Bool {
        get { flags.contains(.closed) }
        set { if newValue { flags.insert(.closed) } else { flags.remove(.closed) } }
    }
    var unidirectional: Bool {
        get { flags.contains(.unidirectional) }
        set { if newValue { flags.insert(.unidirectional) } else { flags.remove(.unidirectional) } }
    }
    var stopSendRequested: Bool {
        get { flags.contains(.stopSendRequested) }
        set {
            if newValue {
                flags.insert(.stopSendRequested)
            } else {
                flags.remove(.stopSendRequested)
            }
        }
    }
    var resetSent: Bool {
        get { flags.contains(.resetSent) }
        set {
            if newValue {
                flags.insert(.resetSent)
            }
            // This is a trap door value: once set, it can't be unset
        }
    }

    var pendingReportReady: Bool { flags.contains(.pendingReportReady) }
    var receivedStopSending: Bool {
        get { flags.contains(.receivedStopSending) }
        set {
            if newValue {
                flags.insert(.receivedStopSending)
            }
            // This is a trap door value: once set, it can't be unset
        }
    }
    var resetReceived: Bool {
        get { flags.contains(.resetReceived) }
        set {
            if newValue {
                flags.insert(.resetReceived)
            }
            // This is a trap door value: once set, it can't be unset
        }
    }
    var hasAdvertisedMaxStreamData: Bool {
        get { flags.contains(.hasAdvertisedMaxStreamData) }
        set {
            if newValue {
                flags.insert(.hasAdvertisedMaxStreamData)
            }
            // This is a trap door value: once set, it can't be unset
        }
    }
    var peerAcknowledgedFIN: Bool {
        get { flags.contains(.peerAcknowledgedFIN) }
        set {
            if newValue {
                flags.insert(.peerAcknowledgedFIN)
            }
            // This is a trap door value: once set, it can't be unset
        }
    }
    var markedInboundFINOnFrame: Bool {
        get { flags.contains(.markedInboundFINOnFrame) }
        set {
            if newValue {
                flags.insert(.markedInboundFINOnFrame)
            }
            // This is a trap door value: once set, it can't be unset
        }
    }
    var applicationMarkedIdle: Bool {
        get { flags.contains(.applicationMarkedIdle) }
        set { if newValue { flags.insert(.applicationMarkedIdle) } else { flags.remove(.applicationMarkedIdle) } }
    }

    func setup(
        streamID: QUICStreamID?,
        logPrefixer: LogPrefixer
    ) {
        self.streamID = streamID
        #if !DisableDebugLogging
        let streamIDString = if let streamID { streamID.description } else { "?" }
        self.log.logPrefix = "[S\(streamIDString)]"
        #endif
        if let _streamID = self.streamID {
            self.streamMetadata.streamID = _streamID.value
            self.streamMetadata.streamType = _streamID.quicStreamType
        }
    }

    func resetStreamID(streamID: QUICStreamID) {
        self.streamID = streamID
        #if !DisableDebugLogging
        self.log.logPrefix = "[S\(streamID.description)]"
        #endif
        if streamID.isUnidirectional {
            self.unidirectional = true
        }

        self.streamMetadata.streamID = streamID.value
        self.streamMetadata.streamType = streamID.quicStreamType
    }

    deinit {
        if let streamID = streamID {
            log.debug("Deallocating unassigned stream \(streamID.value)")
        } else {
            log.debug("Deallocating unassigned stream")
        }
    }

    func teardown(in eventContext: inout NetworkContext.EventContext) {
        guard !self.closed else { return }
        parentProtocol.handleStreamClose(stream: self, error: nil, in: &eventContext)
    }

    func close(errorCode: NetworkError?, in eventContext: inout NetworkContext.EventContext) {
        parentProtocol.handleStreamClose(stream: self, error: errorCode, in: &eventContext)
    }

    /// Releases this stream's event state from outside the protocol stack, for tests only.
    func destroyFromExternalTest() {
        fromExternal { eventContext in
            unregisterEventManager(in: &eventContext)
        }
    }

    public func abortOutbound(error: NetworkError?, in eventContext: inout NetworkContext.EventContext) {
        self.outboundApplicationError = UInt64(error?.quicApplicationError ?? 0)
        let parent = parentProtocol
        _ = parent.handleStopWrite(for: self)
        parent.coreAfterUpdate(in: &eventContext)
    }

    public func abortInbound(error: NetworkError?, in eventContext: inout NetworkContext.EventContext) {
        self.inboundApplicationError = UInt64(error?.quicApplicationError ?? 0)
        let parent = parentProtocol
        parent.handleStopRead(for: self)
        parent.coreAfterUpdate(in: &eventContext)
    }

    var isOpen: Bool {

        !(self.pendingStart || self.closed
            || (self.send.state == .invalid && self.receive.state == .invalid))
    }

    var streamType: QUICStreamType? { self.streamID?.quicStreamType }

    override public func upperReceiveQueueDrainedBytes(_ bytes: Int, in eventContext: inout NetworkContext.EventContext)
    {
        self.parentProtocol.coreStreamDrained(self, in: &eventContext)
    }

    func inboundStreamReady() {
        let logPrefix = log.logPrefix
        receive.state.change(logIDString: logPrefix, to: .receive)
        if !unidirectional {
            send.state.change(logIDString: logPrefix, to: .ready)
        }
    }

    func outboundStreamReady() {
        let logPrefix = log.logPrefix
        if !self.unidirectional {
            self.receive.state.change(logIDString: logPrefix, to: .receive)
        }
        self.send.state.change(logIDString: logPrefix, to: .ready)
    }
}

// MARK: Utility on Stream

@available(Network 0.1.0, *)
extension QUICStreamInstance {
    static func isValid(isServer: Bool, streamID: QUICStreamID) -> Bool {
        if !isServer && streamID.isClientInitiated {
            // Note that this is client reasoning about a peer streamID
            return false
        } else if isServer && streamID.isServerInitiated {
            // Note that this is server reasoning about a peer streamID
            return false
        }
        return true
    }
}

// MARK: Flow Control - Limits

#endif
