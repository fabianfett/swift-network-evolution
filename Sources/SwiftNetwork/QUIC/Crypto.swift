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

#if canImport(SwiftSystem)
internal import SwiftSystem
#endif

#if IMPORT_CRYPTO || IMPORT_SWIFTTLS
#if canImport(CryptoKit)
internal import CryptoKit
#elseif canImport(Crypto)
@preconcurrency internal import Crypto
#endif
#endif

#if IMPORT_SWIFTTLS && canImport(SwiftTLS)
#if EXPORT_SWIFTTLS
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS
#else
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) @_weakLinked internal import SwiftTLS
#endif
#endif

/// Runs the TLS handshake for a QUIC connection.
///
/// Drives `SwiftTLSHandshaker` directly: CRYPTO frame data goes in through `appendInput`, handshake
/// messages come back out through the per-level send buffers the packet builder pulls from, and
/// keys and transport parameters are handed straight to the connection.
@available(Network 0.1.0, *)
final class QUICCrypto {
    #if CLIENT_ONLY
    private var handshaker: SwiftTLSHandshaker? = SwiftTLSHandshaker.createClientHandshake()
    #else
    #if SERVER_ONLY
    private var handshaker: SwiftTLSHandshaker? = SwiftTLSHandshaker.createServerHandshake()
    #else
    // Client or server case
    private var handshaker: SwiftTLSHandshaker? = SwiftTLSHandshaker.createClientHandshake()
    #endif
    #endif

    private var isServer = false
    private var serverSentHello = false
    private var startedHandshake = false
    private var tlsOptions = SwiftTLSProtocol.Options()

    /// Whether the handshake is running and takes CRYPTO data: from `start` until `stop`.
    private var isHandshakeLinked = false

    /// Connected and disconnected handshake events, which are delivered once the current handshake
    /// step returns, and at most one of each, connected first.
    private enum HandshakeEvent {
        case connected
        case disconnected(NetworkError?)
    }
    private enum HandshakeConnectedState {
        case initial
        case connected
        case disconnected
    }
    private var handshakeConnectedState = HandshakeConnectedState.initial
    private var pendingHandshakeEvents: [HandshakeEvent] = []

    var outboundCryptoInitialOffset: Int = 0
    var outboundCrypto1RTTOffset: Int = 0
    var outboundCryptoHandshakeOffset: Int = 0

    var parentConnection: QUICConnection?

    var initialReassemblyQueue = ReassemblyQueue()
    var handshakeReassemblyQueue = ReassemblyQueue()
    var applicationReassemblyQueue = ReassemblyQueue()

    var initialOutboundData = StreamSendBuffer()
    var handshakeOutboundData = StreamSendBuffer()
    var applicationOutboundData = StreamSendBuffer()
    var initialOutboundDataOffset: UInt64 = 0
    var handshakeOutboundDataOffset: UInt64 = 0
    var applicationOutboundDataOffset: UInt64 = 0

    var ciphersuite: Int = 0

    var enableEarlyData = false

    static let bufferLimit: Int = 4 * 1024

    #if canImport(SwiftTLS) && SWIFTTLS_CERTIFICATE_VERIFICATION
    /// What the certificate-verification continuation reaches this object through.
    ///
    /// SwiftTLS copies the continuation handler into its handshake state machine, and clearing
    /// the handler does not clear that copy, so the closure outlives the handshake. It holds
    /// this box rather than the object, and stopping the handshake empties the box, which
    /// is what lets the object go.
    ///
    /// The box crosses into the continuation closure, which runs wherever SwiftTLS completes the
    /// verification, so it has to be `Sendable`; `crypto` is only ever read back on the
    /// context, which is what makes that sound.
    private final class AsyncContinuationTarget: @unchecked Sendable {
        var crypto: QUICCrypto?

        init(_ crypto: QUICCrypto) {
            self.crypto = crypto
        }
    }

    private var asyncContinuationTarget: AsyncContinuationTarget?
    #endif

    init() {}

    init(context: NetworkContext) {}

    init(context: NetworkContext, in eventContext: inout NetworkContext.EventContext) {}

    func start(
        with parentConnection: QUICConnection,
        tlsOptions inputTLSOptions: SwiftTLSProtocol.Options,
        in eventContext: inout NetworkContext.EventContext
    ) -> Bool {
        self.parentConnection = parentConnection

        initialReassemblyQueue.log = NetworkLoggerState("[TLS-Initial]")
        handshakeReassemblyQueue.log = NetworkLoggerState("[TLS-Handshake]")
        applicationReassemblyQueue.log = NetworkLoggerState("[TLS-Application]")

        enableEarlyData = inputTLSOptions.enableEarlyData

        // Set up values on tlsOptions
        var mutableTLSOptions = inputTLSOptions

        if let transportParameterBytes = try? parentConnection.localTransportParameters.serialize() {
            mutableTLSOptions.quicTransportParameters = transportParameterBytes
        }

        guard mutableTLSOptions.tlsOptions.quicTransportParameters != nil else {
            parentConnection.log.error("Failed to attach TLS protocol")
            return false
        }
        self.tlsOptions = mutableTLSOptions
        self.isServer = parentConnection.isServer

        startHandshake(on: parentConnection, in: &eventContext)
        deliverPendingHandshakeEvents(in: &eventContext)
        return true
    }

    private func startHandshake(on parentConnection: QUICConnection, in eventContext: inout NetworkContext.EventContext)
    {
        guard !startedHandshake else {
            // Already started, ignore
            return
        }

        startedHandshake = true
        #if CLIENT_ONLY
        if isServer {
            parentConnection.log.error("Server TLS not supported")
            reportError(EINVAL)
            return
        }
        #else
        #if SERVER_ONLY
        if !isServer {
            parentConnection.log.error("Client TLS not supported")
            reportError(EINVAL)
            return
        }
        #else
        if isServer {
            // Switch to server mode
            handshaker = SwiftTLSHandshaker.createServerHandshake()
        }
        #endif
        #endif
        guard let handshaker else { return }

        isHandshakeLinked = true

        #if canImport(SwiftTLS) && SWIFTTLS_CERTIFICATE_VERIFICATION
        let target = AsyncContinuationTarget(self)
        asyncContinuationTarget = target
        // SwiftTLS delivers async results on whatever thread completed the work, so hop onto
        // the context before touching this object or the event state. `NetworkContext.async`
        // doesn't read the event state, so it is safe to call from any thread.
        let context = parentConnection.context
        handshaker.setAsyncContinuationHandler { result in
            context.async {
                guard let crypto = target.crypto, let handshaker = crypto.handshaker else { return }
                handshaker.setAsyncResult(result)
                crypto.continueHandshake(in: &context.eventContext)
                crypto.deliverPendingHandshakeEvents(in: &context.eventContext)
            }
        }
        #endif

        if isServer {
            do {
                let handshakeBytes = try handshaker.setupHandshake(options: tlsOptions.tlsOptions)
                guard handshakeBytes == nil else {
                    parentConnection.log.error("Server handshaker unexpectedly set up bytes")
                    reportError(EINVAL)
                    return
                }
            } catch {
                parentConnection.log.error("Failed to set up server handshaker")
                reportError(EINVAL)
                return
            }
        } else {
            guard let handshakeBytesToSend = try? handshaker.setupHandshake(options: tlsOptions.tlsOptions) else {
                parentConnection.log.error("Failed to set up client handshaker")
                reportError(EINVAL)
                return
            }

            sendMessage(handshakeBytesToSend, level: .initial, in: &eventContext)
        }

        // Update the encryption secrets for early data
        if handshaker.writeEncryptionLevel != .initial {
            if handshaker.writeEncryptionLevel == .earlyData,
                let earlyDataTransportParameters = tlsOptions.resumedQUICTransportParameters
            {
                updatePeerQUICTransportParameters(
                    earlyDataTransportParameters,
                    earlyData: true,
                    in: &eventContext
                )
            }

            updateNegotiatedCiphersuite(handshaker.negotiatedCiphersuite)
            if let readSecret = handshaker.readEncryptionSecret {
                updateSecret(
                    readSecret,
                    for: handshaker.readEncryptionLevel,
                    isWrite: false,
                    in: &eventContext
                )
            }
            if let writeSecret = handshaker.writeEncryptionSecret {
                updateSecret(
                    writeSecret,
                    for: handshaker.writeEncryptionLevel,
                    isWrite: true,
                    in: &eventContext
                )
            }
        }
    }

    /// Stops using an event context the caller already holds.
    func stop(in eventContext: inout NetworkContext.EventContext) {
        guard self.parentConnection != nil else {
            // Never started, or already stopped.
            releaseHandshake()
            return
        }
        isHandshakeLinked = false

        initialOutboundData.empty()
        handshakeOutboundData.empty()
        applicationOutboundData.empty()
        initialReassemblyQueue.dequeueAll()
        handshakeReassemblyQueue.dequeueAll()
        applicationReassemblyQueue.dequeueAll()

        releaseHandshake()

        self.parentConnection = nil
    }

    /// Lets go of the handshake.
    private func releaseHandshake() {
        #if canImport(SwiftTLS) && SWIFTTLS_CERTIFICATE_VERIFICATION
        handshaker?.setAsyncContinuationHandler(nil)
        // SwiftTLS's state machine keeps its own copy of the continuation closure, so emptying the
        // box is what stops that copy from holding this object.
        asyncContinuationTarget?.crypto = nil
        asyncContinuationTarget = nil
        #endif
        self.handshaker = nil
    }

    func currentOffset(for level: PacketNumberSpace) -> Int {
        switch level {
        case .initial:
            return outboundCryptoInitialOffset
        case .handshake:
            return outboundCryptoHandshakeOffset
        case .applicationData:
            return outboundCrypto1RTTOffset
        }
    }

    func sendAtLevel(_ level: PacketNumberSpace, in eventContext: inout NetworkContext.EventContext) {
        guard let parentConnection else {
            return
        }
        inScope(of: parentConnection, in: &eventContext) { eventContext in
            markSendPending(level, on: parentConnection)
            guard parentConnection.sendFrames(in: &eventContext) else {
                parentConnection.log.error("Unable to send Crypto Frames")
                return
            }
        }
    }

    /// Runs `body` with `parentConnection`'s event state entered.
    func inScope(
        of parentConnection: QUICConnection,
        in eventContext: inout NetworkContext.EventContext,
        _ body: (inout NetworkContext.EventContext) -> Void
    ) {
        parentConnection.identifier.fromExternal(in: &eventContext) { eventContext in
            guard !parentConnection.deferClosing else {
                body(&eventContext)
                return
            }
            parentConnection.deferClosing = true
            body(&eventContext)
            parentConnection.deferClosing = false
            guard parentConnection.closeError != nil else {
                return
            }
            // The event state is held here, so this takes the `in:` variant: the external entry
            // point would acquire it a second time, which is an exclusivity violation.
            parentConnection.async(in: &eventContext) { asyncContext in
                if parentConnection.closeError != nil {
                    parentConnection.close(sendCloseFrame: true, in: &asyncContext)
                }
            }
        }
    }

    // Notify pending items that there are crypto bytes to get!
    private func markSendPending(_ level: PacketNumberSpace, on parentConnection: QUICConnection) {
        if level == .initial {
            parentConnection.initialPendingItems.sendCrypto = true
        } else if level == .handshake {
            parentConnection.handshakePendingItems.sendCrypto = true
        } else {
            parentConnection.applicationPendingItems.sendCrypto = true
        }
    }
}

// MARK: Handshake

@available(Network 0.1.0, *)
extension QUICCrypto {
    /// Feeds one in-order chunk of CRYPTO data to the handshake.
    private func processHandshakeMessage(_ message: [UInt8], in eventContext: inout NetworkContext.EventContext) {
        do {
            try continueHandshake(with: message, in: &eventContext)
        } catch {
            parentConnection?.log.error("Failed to continue handshake \(error)")
            if let handshakerErrorCode = handshaker?.errorCode, handshakerErrorCode != 0 {
                reportError(handshakerErrorCode)
            }
        }
    }

    /// Continues the handshake once an asynchronous step, such as certificate verification, finished.
    fileprivate func continueHandshake(in eventContext: inout NetworkContext.EventContext) {
        do {
            try continueHandshake(with: nil, in: &eventContext)
        } catch {
            parentConnection?.log.error("Failed to continue handshake \(error)")
            if let handshakerErrorCode = handshaker?.errorCode, handshakerErrorCode != 0 {
                reportError(handshakerErrorCode)
            }
        }
    }

    private func continueHandshake(
        with message: [UInt8]?,
        in eventContext: inout NetworkContext.EventContext
    ) throws(TLSNetworkError) {
        var messageToProcess: [UInt8]? = message
        while let handshaker {

            // Loop to gather all handshake data into one message
            var dataToSend: [UInt8]?
            while true {
                do {
                    let singleData = try handshaker.continueHandshake(with: messageToProcess)
                    if let singleData {
                        // Append to data to send
                        if dataToSend != nil {
                            dataToSend = dataToSend! + singleData
                        } else {
                            dataToSend = singleData
                        }

                        if !serverSentHello {
                            // Need to send the initial server message, break this inner loop
                            break
                        }
                    } else {
                        // No more data to send, break this inner loop
                        break
                    }
                } catch {
                    throw TLSNetworkError.handshakeFailed
                }
            }

            guard dataToSend != nil || messageToProcess != nil else {
                // Exit loop if no progress
                break
            }

            messageToProcess = nil
            if handshaker.earlyDataAccepted {
                updateEarlyDataAccepted(true, in: &eventContext)
            }

            if let peerQUICTransportParameters = handshaker.peerQUICTransportParameters {
                updatePeerQUICTransportParameters(
                    peerQUICTransportParameters,
                    earlyData: false,
                    in: &eventContext
                )
            }

            let hasWriteEncryptionLevel = (handshaker.writeEncryptionLevel != .initial)
            let hasReadEncryptionLevel = (handshaker.readEncryptionLevel != .initial)
            if hasWriteEncryptionLevel || hasReadEncryptionLevel {
                updateNegotiatedCiphersuite(handshaker.negotiatedCiphersuite)
                if hasReadEncryptionLevel, let readSecret = handshaker.readEncryptionSecret {
                    updateSecret(
                        readSecret,
                        for: handshaker.readEncryptionLevel,
                        isWrite: false,
                        in: &eventContext
                    )
                }
                if hasWriteEncryptionLevel, let writeSecret = handshaker.writeEncryptionSecret {
                    updateSecret(
                        writeSecret,
                        for: handshaker.writeEncryptionLevel,
                        isWrite: true,
                        in: &eventContext
                    )
                }
            }

            if !handshaker.receivedSessionTickets.isEmpty {
                let ticketArray = handshaker.receivedSessionTickets
                handshaker.receivedSessionTickets = [[UInt8]]()
                updateSessionTickets(ticketArray)
            }

            if let dataToSend {
                if isServer {
                    if serverSentHello {
                        sendMessage(dataToSend, level: .handshake, in: &eventContext)
                    } else {
                        serverSentHello = true
                        sendMessage(dataToSend, level: .initial, in: &eventContext)
                    }
                } else {
                    sendMessage(dataToSend, level: .handshake, in: &eventContext)
                }
            } else if handshaker.errorCode != 0 {
                reportError(handshaker.errorCode)
            }

            if isServer {
                if handshaker.readEncryptionLevel == .application {
                    completeHandshake()
                }
            } else {
                if handshaker.writeEncryptionLevel == .application {
                    completeHandshake()
                }
            }
        }
    }

    private func completeHandshake() {
        enqueueHandshakeEvent(.connected)
    }

    private func reportError(_ error: Int32) {
        parentConnection?.log.error("Reporting TLS error \(error)")
        enqueueHandshakeEvent(.disconnected(NetworkError.posix(error)))
    }

    private func enqueueHandshakeEvent(_ event: HandshakeEvent) {
        switch event {
        case .connected:
            guard case .initial = handshakeConnectedState else { return }  // Don't deliver a redundant event
            handshakeConnectedState = .connected
        case .disconnected:
            if case .disconnected = handshakeConnectedState { return }  // Don't deliver a redundant event
            handshakeConnectedState = .disconnected
        }
        pendingHandshakeEvents.append(event)
    }

    /// Delivers the connected and disconnected events the last handshake step produced.
    fileprivate func deliverPendingHandshakeEvents(in eventContext: inout NetworkContext.EventContext) {
        while !pendingHandshakeEvents.isEmpty {
            let event = pendingHandshakeEvents.removeFirst()
            switch event {
            case .connected:
                handleConnectedEvent(in: &eventContext)
                if !isServer, let handshaker, !handshaker.earlyDataAccepted {
                    updateEarlyDataAccepted(false, in: &eventContext)
                }
            case .disconnected(let error):
                handleDisconnectedEvent(error: error, in: &eventContext)
            }
        }
    }

    private func sendMessage(
        _ message: [UInt8],
        level: SwiftTLSOptions.EncryptionLevel,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard isHandshakeLinked else {
            return
        }
        let packetNumberSpace: PacketNumberSpace
        switch level {
        case .initial:
            packetNumberSpace = .initial
            initialOutboundData.addSendData(FrameArray(frame: Frame(copyBuffer: message)), isLast: false)
        case .handshake:
            packetNumberSpace = .handshake
            handshakeOutboundData.addSendData(FrameArray(frame: Frame(copyBuffer: message)), isLast: false)
        case .earlyData, .application:
            packetNumberSpace = .applicationData
            applicationOutboundData.addSendData(FrameArray(frame: Frame(copyBuffer: message)), isLast: false)
        }
        sendAtLevel(packetNumberSpace, in: &eventContext)
    }

    func handleConnectedEvent(in eventContext: inout NetworkContext.EventContext) {
        guard let parentConnection else { return }
        inScope(of: parentConnection, in: &eventContext) { eventContext in
            parentConnection.log.info("Connected: TLS finished")
            parentConnection.reportReady(in: &eventContext)
        }
    }

    func handleDisconnectedEvent(error: NetworkError?, in eventContext: inout NetworkContext.EventContext) {
        guard let parentConnection else { return }
        inScope(of: parentConnection, in: &eventContext) { eventContext in
            parentConnection.log.error("Disconnected: TLS error \(error?.description ?? "<none>")")
            parentConnection.closeFrameType = .crypto
            parentConnection.close(withCryptoError: 0, "TLS error", in: &eventContext)
        }
    }
}

#if IMPORT_SWIFTTLS && canImport(SwiftTLS)
@available(Network 0.1.0, *)
extension QUICCrypto {
    func updateSecret(
        _ secret: [UInt8],
        for level: SwiftTLSOptions.EncryptionLevel,
        isWrite: Bool,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let parentConnection else { return }
        inScope(of: parentConnection, in: &eventContext) { eventContext in
            updateSecretInScope(secret, for: level, isWrite: isWrite, on: parentConnection, in: &eventContext)
        }
    }

    private func updateSecretInScope(
        _ secret: [UInt8],
        for level: SwiftTLSOptions.EncryptionLevel,
        isWrite: Bool,
        on parentConnection: QUICConnection,
        in eventContext: inout NetworkContext.EventContext
    ) {
        parentConnection.log.debug(
            "Got \(isWrite ? "write" : "read") secret update for level \(level.debugDescription)"
        )
        guard let tlsCiphersuite = TLSCipherSuite(sslCipherSuite: self.ciphersuite) else {
            return
        }
        parentConnection.protector.keyUpdate(
            for: TLSEncryptionLevel(level),
            cipherSuite: tlsCiphersuite,
            secret: SymmetricKey(data: secret),
            isWrite: isWrite
        )
        if level == .handshake {
            parentConnection.updateSecretForHandshakeLevel()
        }

        // Drop 0-RTT keys once 1-RTT keys are available.
        // NOTE: This only drops keys for clients; servers keep the
        // keys to be able to receive packets.
        if !parentConnection.isServer,
            parentConnection.protector.keysReady(for: .earlyData),
            parentConnection.protector.keysReady(for: .phase0)
        {
            parentConnection.protector.drop(keyState: .earlyData)
        }

        // Start the 0-RTT machinery when we first get 0-RTT write keys.
        if !parentConnection.earlyDataSignalled, parentConnection.state != .connected,
            parentConnection.protector.sealKeyReady(for: .earlyData)
        {

            guard let remoteTransportParameters = parentConnection.remoteTransportParameters,
                parentConnection.remoteTransportParametersForEarlyData
            else {
                parentConnection.log.error(
                    "Early data available without remote transport parameters"
                )
                return
            }

            parentConnection.log.debug("Signaling availability of early data")

            parentConnection.setupFlowControl(
                remoteTransportParameters: remoteTransportParameters,
                in: &eventContext
            )

            parentConnection.earlyDataSignalled = true
            parentConnection.readyAllOutboundStreams(in: &eventContext)
        }
    }

    func updateEncryptionLevel(_ level: SwiftTLSOptions.EncryptionLevel, isWrite: Bool) {
        parentConnection?.log.debug("Got encryption level update: \(level.debugDescription)")
    }

    func updateSessionTickets(_ sessionTicketArray: [[UInt8]]) {
        parentConnection?.log.debug("Got session tickets")
    }

    func updatePeerQUICTransportParameters(
        _ peerQUICTransportParameters: [UInt8],
        earlyData: Bool,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard let parentConnection else {
            return
        }
        inScope(of: parentConnection, in: &eventContext) { eventContext in
            updatePeerQUICTransportParametersInScope(
                peerQUICTransportParameters,
                earlyData: earlyData,
                on: parentConnection,
                in: &eventContext
            )
        }
    }

    private func updatePeerQUICTransportParametersInScope(
        _ peerQUICTransportParameters: [UInt8],
        earlyData: Bool,
        on parentConnection: QUICConnection,
        in eventContext: inout NetworkContext.EventContext
    ) {
        // Allow resetting if we now have non-early-data transport parameters
        guard
            parentConnection.remoteTransportParameters == nil
                || (!earlyData && parentConnection.remoteTransportParametersForEarlyData)
        else {
            return
        }

        // If the client has enabled early data, and we now have complete remote transport parameters,
        // send them up to allow the client to store them for future connections
        if !earlyData, !parentConnection.isServer, enableEarlyData {
            parentConnection.deliverNetworkProtocolEvent(
                flow: .allFlows,
                event: .init(
                    quicEvent: .receivedRemoteTransportParameters(
                        transportParameters: peerQUICTransportParameters
                    )
                ),
                in: &eventContext
            )
        }

        let parameterBytes = peerQUICTransportParameters.span
        do {
            let remoteTransportParameters = try TransportParameters.deserialize(
                parameterBytes,
                logPrefixer: parentConnection.logPrefixer
            )
            parentConnection.setRemoteTransportParameters(
                remoteTransportParameters,
                earlyData: earlyData,
                in: &eventContext
            )
        } catch {
            if earlyData {
                parentConnection.log.error(
                    "Failed to parse transport parameters for early data, ignoring: \(error)"
                )
            } else {
                parentConnection.log.error("Failed to parse transport parameters: \(error)")
                parentConnection.closeFrameType = .crypto
                parentConnection.close(
                    with:
                        .transportParameterError,
                    "Failed to deserialize transport parameters",
                    in: &eventContext
                )
            }
        }

        // Free up memory
        var peerQUICTransportParameters = peerQUICTransportParameters
        peerQUICTransportParameters.removeAll()
    }

    func updateEarlyDataAccepted(_ earlyDataAccepted: Bool, in eventContext: inout NetworkContext.EventContext) {
        guard let parentConnection, parentConnection.earlyDataSignalled else { return }
        inScope(of: parentConnection, in: &eventContext) { eventContext in
            parentConnection.log.debug("Got early data accepted: \(earlyDataAccepted)")
            parentConnection.updateEarlyDataAccepted(earlyDataAccepted, in: &eventContext)
        }
    }

    func updateNegotiatedCiphersuite(_ ciphersuite: Int) {
        parentConnection?.log.debug("Got negotiated ciphersuite: \(ciphersuite)")
        self.ciphersuite = ciphersuite
    }
}
#else
// A build can have QUIC without SwiftTLS, in which case the handshake runs elsewhere and nothing
// ever drives these. They still have to exist, because the SwiftTLS-facing call sites in
// `SwiftTLSProtocol.swift` compile against the stub handshaker.
@available(Network 0.1.0, *)
extension QUICCrypto {
    func updateSecret(
        _ secret: [UInt8],
        for level: SwiftTLSOptions.EncryptionLevel,
        isWrite: Bool,
        in eventContext: inout NetworkContext.EventContext
    ) {}

    func updateEncryptionLevel(_ level: SwiftTLSOptions.EncryptionLevel, isWrite: Bool) {}

    func updateSessionTickets(_ sessionTicketArray: [[UInt8]]) {}

    func updatePeerQUICTransportParameters(
        _ peerQUICTransportParameters: [UInt8],
        earlyData: Bool,
        in eventContext: inout NetworkContext.EventContext
    ) {}

    func updateEarlyDataAccepted(_ earlyDataAccepted: Bool, in eventContext: inout NetworkContext.EventContext) {}

    func updateNegotiatedCiphersuite(_ ciphersuite: Int) {}
}
#endif

// MARK: CRYPTO data

@available(Network 0.1.0, *)
extension QUICCrypto {
    func appendInput(
        _ cryptoFrame: consuming FrameCrypto,
        for packetNumberSpace: PacketNumberSpace,
        reassemblyQueue: inout ReassemblyQueue
    ) -> FrameArray? {
        guard isHandshakeLinked else {
            cryptoFrame.frame.finalize(success: false)
            return nil
        }
        let bufferLimitForPNSpace =
            packetNumberSpace == .handshake ? 2 * QUICCrypto.bufferLimit : QUICCrypto.bufferLimit
        guard reassemblyQueue.size <= bufferLimitForPNSpace else {
            parentConnection?.log.error(
                "Read crypto buffer size \(reassemblyQueue.size) is larger than limit \(bufferLimitForPNSpace)"
            )
            cryptoFrame.frame.finalize(success: false)
            return nil
        }

        guard reassemblyQueue.canAppendItemsForByteLimit(UInt64(bufferLimitForPNSpace)).acceptable else {
            parentConnection?.log.error(
                "Read crypto buffer has too many items, closing"
            )
            cryptoFrame.frame.finalize(success: false)
            return nil
        }

        reassemblyQueue.append(
            frame: cryptoFrame.frame,
            offset: Int(cryptoFrame.offset),
            fin: false
        )
        var inOrderData = FrameArray()
        while let dequeueItem = reassemblyQueue.dequeue() {
            inOrderData.add(frame: dequeueItem.frame)
        }
        return inOrderData
    }

    /// Appends crypto input using an event context the caller already holds, and runs the
    /// handshake on the data that is now in order.
    func appendInput(
        _ cryptoFrame: consuming FrameCrypto,
        for packetNumberSpace: PacketNumberSpace,
        in eventContext: inout NetworkContext.EventContext
    ) -> Bool {
        let inOrderData: FrameArray?
        switch packetNumberSpace {
        case .initial:
            inOrderData = appendInput(cryptoFrame, for: packetNumberSpace, reassemblyQueue: &initialReassemblyQueue)
        case .handshake:
            inOrderData = appendInput(cryptoFrame, for: packetNumberSpace, reassemblyQueue: &handshakeReassemblyQueue)
        case .applicationData:
            inOrderData = appendInput(
                cryptoFrame,
                for: packetNumberSpace,
                reassemblyQueue: &applicationReassemblyQueue
            )
        }
        guard var inOrderData else {
            return false
        }
        while var frame = inOrderData.popFirst() {
            guard isHandshakeLinked else {
                frame.finalize(success: false)
                continue
            }
            if let bytes = frame.span, !bytes.isEmpty {
                processHandshakeMessage([UInt8](copying: bytes, maxCount: bytes.count), in: &eventContext)
            } else {
                frame.finalize(success: false)
                continue
            }

            frame.finalize(success: true)
        }
        deliverPendingHandshakeEvents(in: &eventContext)
        return true
    }
}

// MARK: Outbound CRYPTO data

@available(Network 0.1.0, *)
extension QUICCrypto {
    func copyOutSendData(
        for packetNumberSpace: PacketNumberSpace,
        offset: StreamOffset,
        length: StreamLength,
        into frame: inout Frame
    ) -> StreamLength {
        guard let parentConnection else {
            return 0
        }
        switch packetNumberSpace {
        case .initial:
            return initialOutboundData.copyOutSendData(
                offset: offset,
                length: length,
                into: &frame,
                log: parentConnection.log
            )
        case .handshake:
            return handshakeOutboundData.copyOutSendData(
                offset: offset,
                length: length,
                into: &frame,
                log: parentConnection.log
            )
        case .applicationData:
            return applicationOutboundData.copyOutSendData(
                offset: offset,
                length: length,
                into: &frame,
                log: parentConnection.log
            )
        }
    }

    func remainingOutboundData(
        for packetNumberSpace: PacketNumberSpace
    ) -> (StreamLength, StreamOffset) {
        switch packetNumberSpace {
        case .initial:
            return (
                initialOutboundData.remainingDataLengthToService(
                    currentSendOffset: initialOutboundDataOffset
                ), initialOutboundDataOffset
            )
        case .handshake:
            return (
                handshakeOutboundData.remainingDataLengthToService(
                    currentSendOffset: handshakeOutboundDataOffset
                ), handshakeOutboundDataOffset
            )
        case .applicationData:
            return (
                applicationOutboundData.remainingDataLengthToService(
                    currentSendOffset: applicationOutboundDataOffset
                ), applicationOutboundDataOffset
            )
        }
    }

    func incrementOutboundOffset(for packetNumberSpace: PacketNumberSpace, by offset: StreamOffset) {
        switch packetNumberSpace {
        case .initial: initialOutboundDataOffset += offset
        case .handshake: handshakeOutboundDataOffset += offset
        case .applicationData: applicationOutboundDataOffset += offset
        }
    }

    func storageOutboundStartOffset(for packetNumberSpace: PacketNumberSpace) -> UInt64 {
        switch packetNumberSpace {
        case .initial: initialOutboundData.storageStartOffset
        case .handshake: handshakeOutboundData.storageStartOffset
        case .applicationData: applicationOutboundData.storageStartOffset
        }
    }

    func acknowledged(
        offset: UInt64,
        length: UInt64,
        for packetNumberSpace: PacketNumberSpace
    ) {
        guard let parentConnection else { return }
        switch packetNumberSpace {
        case .initial:
            _ = initialOutboundData.acknowledgedSendData(offset: offset, length: length, log: parentConnection.log)
        case .handshake:
            _ = handshakeOutboundData.acknowledgedSendData(offset: offset, length: length, log: parentConnection.log)
        case .applicationData:
            _ = applicationOutboundData.acknowledgedSendData(offset: offset, length: length, log: parentConnection.log)
        }
    }
}
#endif
