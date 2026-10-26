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

// Error types thrown by the QUIC building blocks.

package enum QUICPacketError: Int, Error {
    case invalidDestinationConnectionID
    case invalidSourceConnectionID
    case invalidVersionNumber
    case serializationBufferTooSmall
    case serializationError
    case invalidHeaderType
    case longheaderKeyStateUpdate  // Attempt to modify keyState while parsing a LH packet.
    case ackNumberUnderflow  // packet number < last acked
    case invalidPacketNumber
    case truncatedPacketNumberTooLarge
    case deserializationError
}

package enum PacketKeyState: Int, CaseIterable, CustomStringConvertible, Comparable {
    case initial = 0
    case handshake
    case earlyData
    case phase0 /* 1-RTT phase 0 */
    case phase1 /* 1-RTT phase 1 */

    package static func < (lhs: PacketKeyState, rhs: PacketKeyState) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    package var description: String {
        switch self {
        case .initial:
            return "initial"
        case .handshake:
            return "handshake"
        case .earlyData:
            return "0-rtt"
        case .phase0:
            return "kp0"
        case .phase1:
            return "kp1"
        }
    }

    package var isHandshakeConfirmed: Bool {
        switch self {
        case .earlyData, .phase0, .phase1:
            return true
        default:
            return false
        }
    }

    package var is1RTT: Bool {
        switch self {
        case .phase0, .phase1:
            return true
        default:
            return false
        }
    }
}

@available(Network 0.1.0, *)
package enum QUICPacketFormatsError: Int, Error {
    case serializationBufferTooSmall
    case unexpectedLength
    case sealingFailure
}

package enum SecFramerError: Int, Error {
    case unsupportedAlgorithm
    case sealingFailed
    case noFramerFound
    case headerProtectionFailed
    case openFailed
}

// QUICError is a common type for representing all exceptions thrown by the QUIC stack
// More granular error types are not used as embedded swift does not support untyped throws

#if !NETWORK_NO_SWIFT_QUIC
@available(Network 0.1.0, *)
package enum QUICError: Error {
    case packet(QUICPacketError)
    case packetFormats(QUICPacketFormatsError)
    #if IMPORT_CRYPTO || IMPORT_SWIFTTLS  // Keep in sync with protector scoping
    case protector(SecFramerError)
    #endif
    case transportParametersDecode(TransportParameterDecodeErrors)
    case transportParametersEncode(TransportParameterEncodeErrors)
    case connectionID(QUICConnectionIDError)

    package var info: (code: Int, description: String) {
        switch self {
        case .packet(let subtype):
            return (subtype.rawValue, "QUIC Packet Exception")
        case .packetFormats(let subtype):
            return (subtype.rawValue, "Packet Formats Exception")
        #if IMPORT_CRYPTO || IMPORT_SWIFTTLS  // Keep in sync with protector scoping
        case .protector(let subtype):
            return (subtype.rawValue, "QUIC Protector Exception")
        #endif
        case .transportParametersDecode(let subtype):
            return (subtype.rawValue, "QUIC Transport Parameters Decode Exception")
        case .transportParametersEncode(let subtype):
            return (subtype.rawValue, "QUIC Transport Parameters Encoder Exception")
        case .connectionID(let subtype):
            return (subtype.rawValue, "QUIC Connection ID error")
        }
    }
}
#else
package enum QUICError: Error {
    case none
}
#endif
