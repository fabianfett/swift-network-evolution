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
// The streams of one direction the application opened that wait for a stream ID: until the
// handshake completes, or until the peer allows more streams.
@available(Network 0.1.0, *)
struct QUICStreamIDState: ~Copyable {
    let logContext: String
    private(set) var pendingStartStreams: [QUICStreamInstance] = []

    init(_ type: QUICStreamType) {
        self.logContext = type == .unidirectional ? "unidirectional" : "bidirectional"
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

#endif
