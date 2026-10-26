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

package enum QUICStreamType: CustomStringConvertible {
    case bidirectional
    case unidirectional

    package var description: String {
        switch self {
        case .bidirectional: return "bidirectional"
        case .unidirectional: return "unidirectional"
        }
    }
}

#if !NETWORK_NO_SWIFT_QUIC
// RFC9000 2.1 Stream Types and Identifiers. We use specific type to ensure type
// safe operations, instead of extending UInt64 for example.
@available(Network 0.1.0, *)
package struct QUICStreamID: Comparable, Hashable {
    // UInt64: A stream ID is a 62-bit integer that is unique for all streams on a connection.
    package private(set) var value: UInt64
    // The least significant bit (0x01) of the stream ID identifies the initiator of the stream.
    private static let initiatorMask: UInt64 = 0x1
    // The second least significant bit (0x02) of the stream ID distinguishes between bidirectional streams
    // (with the bit set to 0) and unidirectional streams (with the bit set to 1).
    private static let typeMask: UInt64 = 0x2
    private static let mask: UInt64 = initiatorMask | typeMask

    // Note: In Swift we deal with "datagram" and "TLS" as entirely different things, so they are not applicable here.

    package static let maxLocalStreams: UInt64 = QUICStreamID.maxLocal + 1
    package static let maxLocal: UInt64 = 0x0fff_ffff_ffff_ffff  // Only 60 bits used locally
    package static let maxValid: UInt64 = 0x3fff_ffff_ffff_ffff  // Up to 62 bits can be used by remote

    package init(_ value: UInt32) {
        self.value = UInt64(value)
    }

    package init?(_ value: UInt64) {
        guard value <= QUICStreamID.maxValid else {
            return nil
        }
        self.value = value
    }

    package init?(_ value: UInt64, serverInitiated: Bool, isUnidirectional: Bool) {
        var streamID = value
        if serverInitiated {
            streamID |= QUICStreamID.initiatorMask
        }
        if isUnidirectional {
            streamID |= QUICStreamID.typeMask  // Unidirectional
        } else {
            streamID &= ~QUICStreamID.typeMask  // Bidirectional
        }
        self.init(streamID)
    }

    package static func setInitiator(value: inout UInt64, isLocal: Bool) {
        if isLocal {
            value &= ~QUICStreamID.initiatorMask
        }
        value |= QUICStreamID.initiatorMask
        return
    }
    package static func setStreamType(value: inout UInt64, isBidir: Bool) {
        if isBidir {
            value &= ~QUICStreamID.typeMask
            return
        }
        value |= QUICStreamID.typeMask
        return
    }
    package static func < (lhs: QUICStreamID, rhs: QUICStreamID) -> Bool {
        lhs.value < rhs.value
    }

    package static func == (lhs: QUICStreamID, rhs: QUICStreamID) -> Bool {
        lhs.value == rhs.value
    }

    // Client-initiated streams have even-numbered stream IDs (with the bit set to 0)
    package var isClientInitiated: Bool { (self.value & QUICStreamID.initiatorMask) == 0 }

    // Server-initiated streams have odd-numbered stream IDs (with the bit set to 1).
    package var isServerInitiated: Bool { (self.value & QUICStreamID.initiatorMask) != 0 }

    package var isBidirectional: Bool { (self.value & QUICStreamID.typeMask) == 0 }

    package var isUnidirectional: Bool { (self.value & QUICStreamID.typeMask) != 0 }

    package func isLocalBidirectional(server: Bool) -> Bool {
        self.isBidirectional
            && ((!server && self.isServerInitiated) || (server && self.isClientInitiated))
    }

    package func isSendOnly(server: Bool) -> Bool {
        self.isUnidirectional
            && ((!server && self.isClientInitiated) || (server && self.isServerInitiated))
    }

    package func isReceiveOnly(server: Bool) -> Bool {
        self.isUnidirectional
            && ((!server && self.isServerInitiated) || (server && self.isClientInitiated))
    }

    package func isInitiatedBy(server: Bool) -> Bool {
        if !server && self.isClientInitiated {
            return true
        } else if server && self.isServerInitiated {
            return true
        }
        return false
    }

    package var quicStreamType: QUICStreamType { self.isBidirectional ? .bidirectional : .unidirectional }

    package func _rawHashValue(seed: Int) -> Int {
        // This is a 'Hashable' fast path which elides the creation of Hasher
        self.value._rawHashValue(seed: seed)
    }
}

// MARK: QUICStreamID computations

@available(Network 0.1.0, *)
extension QUICStreamID {
    package static func computeRemoteMaxStreamIDBidirectional(
        server: Bool,
        streams: UInt64
    ) -> QUICStreamID? {
        guard streams != 0 else { return nil }
        if !server {
            // There is a overflow check in QUICStreamID so this will return nil
            // if the shift overflows.
            return QUICStreamID((streams - 1) << 2)  // 4(n-1)
        } else {
            return QUICStreamID(((streams - 1) << 2) + 1)  // 4(n-1) + 1
        }
    }

    package static func computeRemoteMaxStreamIDUnidirectional(
        server: Bool,
        streams: UInt64
    ) -> QUICStreamID? {
        guard streams != 0 else { return nil }
        if !server {
            return QUICStreamID(((streams - 1) << 2) + 2)  // 4(n-1) + 2
        } else {
            return QUICStreamID(((streams - 1) << 2) + 3)  // 4(n-1) + 3
        }
    }

    package static func computeLocalMaxStreamIDBidirectional(server: Bool, streams: UInt64) -> QUICStreamID? {
        guard streams != 0 else { return nil }
        if !server {
            return QUICStreamID(((streams - 1) << 2) + 1)  // 4(n-1) + 1
        } else {
            return QUICStreamID((streams - 1) << 2)  // 4(n-1)
        }
    }

    package static func computeLocalMaxStreamIDUnidirectional(
        server: Bool,
        streams: UInt64
    ) -> QUICStreamID? {
        guard streams != 0 else { return nil }
        if !server {
            return QUICStreamID(((streams - 1) << 2) + 3)  // 4(n-1) + 3
        } else {
            return QUICStreamID(((streams - 1) << 2) + 2)  // 4(n-1) + 2
        }
    }
}

@available(Network 0.1.0, *)
extension QUICStreamID {
    package var variableLengthSize: Int {
        self.value.variableLengthSize
    }
}

@available(Network 0.1.0, *)
extension QUICStreamID: Strideable {
    package func advanced(by n: Int) -> QUICStreamID {
        QUICStreamID(self.value + UInt64(n))!
    }

    package func distance(to other: QUICStreamID) -> Int {
        Int(other.value - self.value)
    }
}

@available(Network 0.1.0, *)
extension QUICStreamID {
    package static let strideLengthToNextOfSameTypeAndInitiator = 4
    // Advance to next stream ID of same type and initiator.
    // The operation can overflow the valid range of value, so must validate value again.
    package func nextOfSameTypeAndInitiator() -> QUICStreamID? {
        QUICStreamID(
            self.value + UInt64(QUICStreamID.strideLengthToNextOfSameTypeAndInitiator)
        )
    }
}

@available(Network 0.1.0, *)
extension QUICStreamID: CustomStringConvertible {
    package var description: String {
        String(value)
    }
}
#endif
