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

/// The TLS handshake of a QUIC connection, as a value.
///
/// Runs `SwiftTLSHandshaker` on the CRYPTO data of each encryption level, buffers the handshake
/// messages to send per level, and returns what the connection has to act on (keys, the peer's
/// transport parameters, completion, errors) in the order the handshake produced it.
@available(Network 0.1.0, *)
struct CoreHandshake: ~Copyable {
    enum Output {
        case secret(SwiftTLSOptions.EncryptionLevel, [UInt8], isWrite: Bool, cipherSuite: Int)
        case peerTransportParameters([UInt8], earlyData: Bool)
        case earlyDataAccepted(Bool)
        case sessionTickets([[UInt8]])
        case complete
        case failed(Int32)
    }

    private var handshaker: SwiftTLSHandshaker?
    private let isServer: Bool
    private var serverSentHello = false
    private(set) var isComplete = false
    private(set) var failed = false

    /// Outbound CRYPTO data per packet number space.
    var send: [CoreSendBuffer] = [CoreSendBuffer(), CoreSendBuffer(), CoreSendBuffer()]
    /// Inbound CRYPTO data per packet number space.
    var receive: [CoreReceiveBuffer] = [CoreReceiveBuffer(), CoreReceiveBuffer(), CoreReceiveBuffer()]

    static let bufferLimit = 4 * 1024

    init(isServer: Bool) {
        self.isServer = isServer
        #if CLIENT_ONLY
        self.handshaker = SwiftTLSHandshaker.createClientHandshake()
        #elseif SERVER_ONLY
        self.handshaker = SwiftTLSHandshaker.createServerHandshake()
        #else
        self.handshaker =
            isServer ? SwiftTLSHandshaker.createServerHandshake() : SwiftTLSHandshaker.createClientHandshake()
        #endif
    }

    /// Starts the handshake. A client queues its ClientHello.
    mutating func start(tlsOptions: SwiftTLSProtocol.Options, outputs: inout [Output]) {
        guard let handshaker else { return }
        do {
            let bytes = try handshaker.setupHandshake(options: tlsOptions.tlsOptions)
            if self.isServer {
                guard bytes == nil else {
                    self.fail(EINVAL, outputs: &outputs)
                    return
                }
            } else {
                guard let bytes else {
                    self.fail(EINVAL, outputs: &outputs)
                    return
                }
                self.send[PacketNumberSpace.initial].append(bytes)
            }
        } catch {
            self.fail(EINVAL, outputs: &outputs)
            return
        }

        // Early data keys and the resumed transport parameters are available right away.
        if handshaker.writeEncryptionLevel != .initial {
            if handshaker.writeEncryptionLevel == .earlyData,
                let earlyDataTransportParameters = tlsOptions.resumedQUICTransportParameters
            {
                outputs.append(.peerTransportParameters(earlyDataTransportParameters, earlyData: true))
            }
            self.appendSecrets(handshaker, readLevelChanged: true, writeLevelChanged: true, outputs: &outputs)
        }
    }

    /// Adds CRYPTO frame data received in `space` and continues the handshake with what is now
    /// in order.
    mutating func receive(
        offset: UInt64,
        bytes: RawSpan,
        in space: PacketNumberSpace,
        outputs: inout [Output]
    ) -> Bool {
        let limit = space == .handshake ? 2 * Self.bufferLimit : Self.bufferLimit
        guard self.receive[space].bufferedOutOfOrderCount &+ bytes.byteCount <= limit else {
            return false
        }
        do {
            try self.receive[space].insert(offset: offset, bytes: bytes, fin: false)
        } catch {
            return false
        }
        while self.receive[space].readableCount > 0 {
            let message: [UInt8] = self.receive[space].read { bytes in
                (bytes.byteCount, [UInt8](copying: bytes))
            }
            self.continueHandshake(with: message, outputs: &outputs)
        }
        return true
    }

    /// Continues the handshake after an asynchronous step, such as certificate verification.
    mutating func resume(outputs: inout [Output]) {
        self.continueHandshake(with: nil, outputs: &outputs)
    }

    #if canImport(SwiftTLS) && SWIFTTLS_CERTIFICATE_VERIFICATION
    func setAsyncContinuationHandler(_ handler: (@Sendable (PendingAsyncResult) -> Void)?) {
        self.handshaker?.setAsyncContinuationHandler(handler)
    }

    func setAsyncResult(_ result: PendingAsyncResult) {
        self.handshaker?.setAsyncResult(result)
    }
    #endif

    /// Releases the handshaker once the handshake is over.
    mutating func release() {
        #if canImport(SwiftTLS) && SWIFTTLS_CERTIFICATE_VERIFICATION
        self.handshaker?.setAsyncContinuationHandler(nil)
        #endif
        self.handshaker = nil
    }

    private mutating func continueHandshake(with message: [UInt8]?, outputs: inout [Output]) {
        var messageToProcess = message
        while let handshaker {
            // Gather the handshake data into one message.
            var dataToSend: [UInt8]?
            while true {
                do {
                    guard let singleData = try handshaker.continueHandshake(with: messageToProcess) else {
                        break
                    }
                    if dataToSend != nil {
                        dataToSend! += singleData
                    } else {
                        dataToSend = singleData
                    }
                    if !self.serverSentHello {
                        // The server's first flight goes out at the initial level.
                        break
                    }
                } catch {
                    let code = handshaker.errorCode
                    self.fail(code != 0 ? code : EPROTO, outputs: &outputs)
                    return
                }
            }

            guard dataToSend != nil || messageToProcess != nil else {
                break
            }
            messageToProcess = nil

            if handshaker.earlyDataAccepted {
                outputs.append(.earlyDataAccepted(true))
            }
            if let peerQUICTransportParameters = handshaker.peerQUICTransportParameters {
                outputs.append(.peerTransportParameters(peerQUICTransportParameters, earlyData: false))
            }
            let hasWriteEncryptionLevel = handshaker.writeEncryptionLevel != .initial
            let hasReadEncryptionLevel = handshaker.readEncryptionLevel != .initial
            if hasWriteEncryptionLevel || hasReadEncryptionLevel {
                self.appendSecrets(
                    handshaker,
                    readLevelChanged: hasReadEncryptionLevel,
                    writeLevelChanged: hasWriteEncryptionLevel,
                    outputs: &outputs
                )
            }
            if !handshaker.receivedSessionTickets.isEmpty {
                outputs.append(.sessionTickets(handshaker.receivedSessionTickets))
                handshaker.receivedSessionTickets = []
            }

            if let dataToSend {
                if self.isServer && !self.serverSentHello {
                    self.serverSentHello = true
                    self.send[PacketNumberSpace.initial].append(dataToSend)
                } else {
                    self.send[PacketNumberSpace.handshake].append(dataToSend)
                }
            } else if handshaker.errorCode != 0 {
                self.fail(handshaker.errorCode, outputs: &outputs)
                return
            }

            let completed =
                self.isServer
                ? handshaker.readEncryptionLevel == .application
                : handshaker.writeEncryptionLevel == .application
            if completed && !self.isComplete {
                self.isComplete = true
                outputs.append(.complete)
                if !self.isServer && !handshaker.earlyDataAccepted {
                    outputs.append(.earlyDataAccepted(false))
                }
            }
        }
    }

    private func appendSecrets(
        _ handshaker: SwiftTLSHandshaker,
        readLevelChanged: Bool,
        writeLevelChanged: Bool,
        outputs: inout [Output]
    ) {
        let cipherSuite = handshaker.negotiatedCiphersuite
        if readLevelChanged, let readSecret = handshaker.readEncryptionSecret {
            outputs.append(
                .secret(handshaker.readEncryptionLevel, readSecret, isWrite: false, cipherSuite: cipherSuite)
            )
        }
        if writeLevelChanged, let writeSecret = handshaker.writeEncryptionSecret {
            outputs.append(
                .secret(handshaker.writeEncryptionLevel, writeSecret, isWrite: true, cipherSuite: cipherSuite)
            )
        }
    }

    private mutating func fail(_ code: Int32, outputs: inout [Output]) {
        guard !self.failed else { return }
        self.failed = true
        outputs.append(.failed(code))
    }
}

@available(Network 0.1.0, *)
extension Array where Element == CoreSendBuffer {
    subscript(space: PacketNumberSpace) -> CoreSendBuffer {
        get { self[Int(space.rawValue)] }
        _modify { yield &self[Int(space.rawValue)] }
    }
}

@available(Network 0.1.0, *)
extension Array where Element == CoreReceiveBuffer {
    subscript(space: PacketNumberSpace) -> CoreReceiveBuffer {
        get { self[Int(space.rawValue)] }
        _modify { yield &self[Int(space.rawValue)] }
    }
}

#if Fuzzing
@available(Network 0.1.0, *)
extension CoreHandshake {
    /// Marks the handshake complete without TLS, for ``QUICConnectionCore/prepareForFuzzing()``.
    mutating func completeForFuzzing() {
        self.isComplete = true
    }
}
#endif

#endif
