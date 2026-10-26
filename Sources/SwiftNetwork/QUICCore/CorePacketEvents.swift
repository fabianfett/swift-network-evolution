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

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// A packet the connection sent, received or declared lost, which the driver writes to its
    /// qlog. Only recorded with ``Configuration/recordsPacketEvents``.
    public struct PacketEvent: Equatable {
        public enum Kind: Equatable {
            case sent
            case received
            case lost
        }

        public enum PacketType: Equatable {
            case initial
            case handshake
            case zeroRTT
            case oneRTT

            init(_ space: PacketNumberSpace) {
                switch space {
                case .initial: self = .initial
                case .handshake: self = .handshake
                case .applicationData: self = .oneRTT
                }
            }
        }

        /// The type of a frame (RFC 9000 Section 12.4). Both variants of a frame type share one.
        public enum FrameType: Equatable {
            case padding
            case ping
            case ack
            case resetStream
            case stopSending
            case crypto
            case newToken
            case stream
            case maxData
            case maxStreamData
            case maxStreams
            case dataBlocked
            case streamDataBlocked
            case streamsBlocked
            case newConnectionID
            case retireConnectionID
            case pathChallenge
            case pathResponse
            case connectionClose
            case handshakeDone
            case datagram
            case unknown

            init(frameType: UInt64) {
                switch frameType {
                case 0x00: self = .padding
                case 0x01: self = .ping
                case 0x02, 0x03: self = .ack
                case 0x04: self = .resetStream
                case 0x05: self = .stopSending
                case 0x06: self = .crypto
                case 0x07: self = .newToken
                case 0x08...0x0f: self = .stream
                case 0x10: self = .maxData
                case 0x11: self = .maxStreamData
                case 0x12, 0x13: self = .maxStreams
                case 0x14: self = .dataBlocked
                case 0x15: self = .streamDataBlocked
                case 0x16, 0x17: self = .streamsBlocked
                case 0x18: self = .newConnectionID
                case 0x19: self = .retireConnectionID
                case 0x1a: self = .pathChallenge
                case 0x1b: self = .pathResponse
                case 0x1c, 0x1d: self = .connectionClose
                case 0x1e: self = .handshakeDone
                case 0x30, 0x31: self = .datagram
                default: self = .unknown
                }
            }

            init(_ frame: CoreSentFrame) {
                switch frame {
                case .ack: self = .ack
                case .crypto: self = .crypto
                case .stream: self = .stream
                case .resetStream: self = .resetStream
                case .stopSending: self = .stopSending
                case .maxData: self = .maxData
                case .maxStreamData: self = .maxStreamData
                case .maxStreamsBidirectional, .maxStreamsUnidirectional: self = .maxStreams
                case .dataBlocked: self = .dataBlocked
                case .streamDataBlocked: self = .streamDataBlocked
                case .newConnectionID: self = .newConnectionID
                case .retireConnectionID: self = .retireConnectionID
                case .pathResponse: self = .pathResponse
                case .pathChallenge: self = .pathChallenge
                case .handshakeDone: self = .handshakeDone
                case .ping, .keepAlive: self = .ping
                case .datagram: self = .datagram
                }
            }
        }

        public var kind: Kind
        public var packetType: PacketType
        public var packetNumber: UInt64
        /// The packet's length, header and tag included.
        public var size: Int
        /// The packet's frames in order; empty for a lost packet.
        public var frames: [FrameType]
        public var time: NetworkClock.Instant
    }

    /// The oldest packet event not taken yet, if any.
    public mutating func nextPacketEvent() -> PacketEvent? {
        self.packetEvents.popFirst()
    }

    mutating func recordPacketEvent(_ event: PacketEvent) {
        self.packetEvents.append(event)
    }

    mutating func recordSentPacket(
        _ packetNumber: UInt64,
        type: PacketEvent.PacketType,
        size: Int,
        frames: [CoreSentFrame],
        hasPadding: Bool,
        now: NetworkClock.Instant
    ) {
        var frameTypes = frames.map(PacketEvent.FrameType.init)
        if hasPadding {
            frameTypes.append(.padding)
        }
        self.recordPacketEvent(
            PacketEvent(
                kind: .sent,
                packetType: type,
                packetNumber: packetNumber,
                size: size,
                frames: frameTypes,
                time: now
            )
        )
    }

    /// Records the packet whose frames were just processed.
    mutating func recordReceivedPacket(
        _ packetNumber: UInt64,
        type: PacketEvent.PacketType,
        size: Int,
        now: NetworkClock.Instant
    ) {
        self.recordPacketEvent(
            PacketEvent(
                kind: .received,
                packetType: type,
                packetNumber: packetNumber,
                size: size,
                frames: self.receivedFrameTypes,
                time: now
            )
        )
        self.receivedFrameTypes.removeAll(keepingCapacity: true)
    }

    mutating func recordPacketEvent(
        _ kind: PacketEvent.Kind,
        sent packet: CoreSentPacket,
        in space: PacketNumberSpace,
        now: NetworkClock.Instant
    ) {
        self.recordPacketEvent(
            PacketEvent(
                kind: kind,
                packetType: PacketEvent.PacketType(space),
                packetNumber: packet.packetNumber,
                size: packet.size,
                frames: [],
                time: now
            )
        )
    }
}

#endif
