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

/// Where 0-RTT stands (RFC 9000 Section 4.6.1, RFC 9001 Section 4.6).
@available(Network 0.1.0, *)
enum CoreEarlyDataState {
    /// No 0-RTT on this connection.
    case none
    /// A client sends 0-RTT packets, with the transport parameters it remembered.
    case attempting
    case accepted
    /// The server rejected the 0-RTT packets; none of them arrived.
    case rejected
}

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// Whether a client sends 0-RTT packets now: until the handshake completes, with the keys and
    /// transport parameters of an earlier connection.
    public var canSendEarlyData: Bool {
        !self.isServer && self.earlyData == .attempting && !self.handshake.isComplete
            && self.protector.sealKeyReady(for: .earlyData) && self.peerTransportParameters != nil
    }

    /// Whether the server accepted this client's 0-RTT packets, or this server accepted the
    /// client's.
    public var isEarlyDataAccepted: Bool {
        self.earlyData == .accepted
    }

    /// The frames of a 0-RTT packet are what the application has to send: no ACK or CRYPTO, and
    /// nothing about paths or connection IDs (RFC 9000 Section 12.4).
    static func isAllowedInEarlyData(_ frameType: UInt64) -> Bool {
        switch frameType {
        case 0x02, 0x03,  // ACK
            0x06,  // CRYPTO
            0x07,  // NEW_TOKEN
            0x19,  // RETIRE_CONNECTION_ID
            0x1b,  // PATH_RESPONSE
            0x1e:  // HANDSHAKE_DONE
            return false
        default:
            return true
        }
    }

    /// Whether there is anything a 0-RTT packet may carry.
    var hasEarlyDataFramesToSend: Bool {
        self.maxDataPending || self.streams.maxStreamsBidirectionalPending
            || self.streams.maxStreamsUnidirectionalPending || !self.datagramsToSend.isEmpty
            || self.hasSendableStreams || self.hasInjectedFrames
    }

    /// A client starts with the transport parameters it remembered for 0-RTT.
    mutating func rememberEarlyDataTransportParameters(_ parameters: TransportParameters) {
        guard !self.isServer else { return }
        self.rememberedTransportParameters = parameters
        self.earlyData = .attempting
    }

    /// The handshake told whether the 0-RTT packets were accepted.
    mutating func earlyDataResolved(accepted: Bool, now: NetworkClock.Instant) {
        if self.isServer {
            if accepted { self.earlyData = .accepted }
            return
        }
        guard self.earlyData == .attempting else { return }
        if accepted {
            self.earlyData = .accepted
            return
        }
        self.earlyData = .rejected
        self.log.info("The server rejected 0-RTT")
        self.protector.drop(keyState: .earlyData)
        // Every 1-RTT packet so far was a 0-RTT packet, and none of them arrived. They aren't
        // losses for congestion control (RFC 9002 Section 6.4).
        let sent = Array(self.recovery.spaces[Int(PacketNumberSpace.applicationData.rawValue)].sent)
        self.recovery.discard(.applicationData)
        if self.configuration.resendRejectedEarlyData {
            for packet in sent {
                self.requeueFrames(of: packet, in: .applicationData)
            }
        } else {
            // The application starts its streams over (RFC 9001 Section 4.6.2).
            self.sentData = 0
            self.streams.forEachStream { stream in
                guard stream.canSend else { return }
                stream.send = CoreSendBuffer()
            }
        }
        // The streams get the limits of this connection, not the remembered ones.
        if let parameters = self.peerTransportParameters {
            self.streams.forEachStream { stream in
                guard stream.canSend else { return }
                stream.sendLimit =
                    CoreStreamMap.isBidirectional(stream.id)
                    ? UInt64(parameters.intValue(.initialMaxStreamDataBidirectionalRemote))
                    : UInt64(parameters.intValue(.initialMaxStreamDataUnidirectional))
            }
        }
        self.events.append(.earlyDataRejected)
    }

    /// A server that accepted 0-RTT must not lower the limits the client used for it (RFC 9000
    /// Section 7.4.1, RFC 9221 Section 3). Returns what it lowered, if anything.
    func earlyDataLimitViolation(_ parameters: TransportParameters) -> String? {
        guard !self.isServer, self.earlyData == .accepted, let remembered = self.rememberedTransportParameters else {
            return nil
        }
        let limits: [(TransportParameterTypes, String)] = [
            (.activeConnectionIDLimit, "active_connection_id_limit"),
            (.initialMaxData, "initial_max_data"),
            (.initialMaxStreamDataBidirectionalLocal, "initial_max_stream_data_bidi_local"),
            (.initialMaxStreamDataBidirectionalRemote, "initial_max_stream_data_bidi_remote"),
            (.initialMaxStreamDataUnidirectional, "initial_max_stream_data_uni"),
            (.initialMaxStreamsBidirectional, "initial_max_streams_bidi"),
            (.initialMaxStreamsUnidirectional, "initial_max_streams_uni"),
            (.maxDatagramFrameSize, "max_datagram_frame_size"),
        ]
        for (id, name) in limits where parameters.intValue(id) < remembered.intValue(id) {
            return "Server reduced \(name)"
        }
        return nil
    }
}

#endif
