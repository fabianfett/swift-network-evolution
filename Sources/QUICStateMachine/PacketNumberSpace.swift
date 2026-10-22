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

#if !NETWORK_NO_SWIFT_QUIC

#if canImport(BasicContainers)
import BasicContainers
package import DequeModule
#endif

#if canImport(Glibc)
import Glibc
package import Logging
#elseif canImport(Android)
import Android
package import Logging
#elseif canImport(Musl)
import Musl
package import Logging
#elseif canImport(os)
package import os
#endif

@available(Network 0.1.0, *)
package struct PacketIdentifier: Comparable {
    package static func < (lhs: PacketIdentifier, rhs: PacketIdentifier) -> Bool {
        if lhs.space == rhs.space {
            return lhs.number < rhs.number
        }
        return lhs.space < rhs.space
    }

    private let _space: PacketNumberSpace
    private var _number: PacketNumber

    package init(space: PacketNumberSpace, number: PacketNumber) {
        self._space = space
        self._number = number
    }

    package var space: PacketNumberSpace {
        _space
    }
    package var number: PacketNumber {
        get { _number }
        set(newValue) {
            _number = newValue
        }
    }
}

package struct EncodedPacketNumber {
    package enum Size: Int, CaseIterable {
        case oneByte = 1
        case twoBytes = 2
        case threeBytes = 3
        case fourBytes = 4

        package init?(rawValue: Int) {
            switch rawValue {
            case 1:
                self = .oneByte
            case 2:
                self = .twoBytes
            case 3:
                self = .threeBytes
            case 4:
                self = .fourBytes
            default:
                return nil
            }
        }
    }

    package let number: Int64
    package let size: Size

    package init(number: Int64, size: Size) {
        self.number = number
        self.size = size
    }
    package var headerFieldSize: UInt8 {  // The QUIC packet header bit field values
        switch size {
        case .oneByte:
            return 0x00
        case .twoBytes:
            return 0x01
        case .threeBytes:
            return 0x02
        case .fourBytes:
            return 0x03
        }
    }
}

@available(Network 0.1.0, *)
package struct PacketNumber: Comparable, ExpressibleByIntegerLiteral, Hashable, CustomStringConvertible {

    package init(integerLiteral value: Int64) {
        self.value = value
    }

    package typealias IntegerLiteralType = Int64

    package var description: String {
        "PacketNumber(\(value))"
    }

    package var value: Int64
    package static let initial = PacketNumber(0)  // Initial path in MPQUIC
    package static let none = PacketNumber(-1)
    package static let max = PacketNumber(0x3fff_FFFF_FFFF_FFFF)

    package init(_ value: Int64) {
        self.value = value
    }

    package init(_ value: UInt64) {
        self.value = Int64(truncatingIfNeeded: value)
    }

    package func isValid() -> Bool {
        self >= .initial && self <= PacketNumber.max
    }

    package static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.value == rhs.value
    }

    package static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.value < rhs.value
    }

    package static func < (lhs: Int64, rhs: Self) -> Bool {
        lhs < rhs.value
    }

    package static func < (lhs: Self, rhs: Int64) -> Bool {
        lhs.value < rhs
    }

    package static func > (lhs: Self, rhs: Int64) -> Bool {
        lhs.value > rhs
    }

    package static func >= (lhs: Self, rhs: Int64) -> Bool {
        lhs.value >= rhs
    }

    package static func + (lhs: Self, rhs: Self) -> Self {
        PacketNumber(lhs.value + rhs.value)
    }

    package static func + (lhs: Self, rhs: Int64) -> Self {
        PacketNumber(lhs.value + rhs)
    }

    package static func - (lhs: Self, rhs: Self) -> Self {
        PacketNumber(lhs.value - rhs.value)
    }

    package static func - (lhs: Self, rhs: Int64) -> Self {
        PacketNumber(lhs.value - rhs)
    }

    package static func * (lhs: Self, rhs: Self) -> Self {
        PacketNumber(lhs.value * rhs.value)
    }

    package static func / (lhs: Self, rhs: Self) -> Self {
        PacketNumber(lhs.value / rhs.value)
    }

    package static func -= (lhs: inout Self, rhs: Self) {
        lhs.value -= rhs.value
    }

    package static func += (lhs: inout Self, rhs: Self) {
        lhs.value += rhs.value
    }

    package func byteLength() -> Int {
        if self == PacketNumber.none {
            return 0
        }
        if self == PacketNumber.initial {
            return 1
        }
        if self == PacketNumber.max {
            return 8
        }
        let bits = MemoryLayout<Int64>.size * 8 - value.leadingZeroBitCount
        return (bits + 7) / 8
    }

    @inline(always)
    package func encode(
        lastAcked: PacketNumber,
        fixedSize: EncodedPacketNumber.Size? = nil
    ) throws(QUICError) -> EncodedPacketNumber {
        if self == .none {
            throw QUICError.packet(QUICPacketError.invalidPacketNumber)
        }

        // check for packet number not greater than lastAcked.
        // If lastAcked == .none the peer has not yet acknowledged anything in this packet number space
        if lastAcked != .none, self <= lastAcked {
            outlinedProtoLogError("Ack number underflow; number, lastAcked", self.value, lastAcked.value)
            throw QUICError.packet(QUICPacketError.ackNumberUnderflow)
        }

        let numUnacked = (lastAcked == .none) ? (self.value + 1) : (self.value - lastAcked.value)

        let difference = numUnacked * 2 + 1
        var truncatedPacketNumber = self.value
        var size: EncodedPacketNumber.Size
        if let fixedSize {
            outlinedProtoLogError("WARNING: Use overrideSentNumberSize only for unit testing!")
            size = fixedSize
        } else {
            if difference <= 0xff {
                truncatedPacketNumber &= 0xff
                size = .oneByte
            } else if difference <= 0xff_ff {
                truncatedPacketNumber &= 0xff_ff
                size = .twoBytes
            } else if difference <= 0xff_ff_ff {
                truncatedPacketNumber &= 0xff_ff_ff
                size = .threeBytes
            } else if difference <= 0xff_ff_ff_ff {
                truncatedPacketNumber &= 0xff_ff_ff_ff
                size = .fourBytes
            } else {
                // Note: the maximum truncated packet number size is 4-bytes.
                // Both LH and SH packets only reserve the least significant 2-bits of the first byte
                // for packet number length.
                // See RFC 9000: section 17.2 (long header) and section 17.3 (short header)
                throw QUICError.packet(QUICPacketError.truncatedPacketNumberTooLarge)
            }
        }

        return EncodedPacketNumber(number: truncatedPacketNumber, size: size)
    }
}

@available(Network 0.1.0, *)
package enum PacketNumberSpace: UInt8, Comparable, CaseIterable {
    case initial = 0
    case handshake = 1
    case applicationData = 2
    @inline(always)
    package static func fromKeyState(keyState: PacketKeyState) -> PacketNumberSpace {
        switch keyState {
        case .earlyData, .phase0, .phase1:
            return .applicationData
        case .initial:
            return .initial
        case .handshake:
            return .handshake
        }
    }
    package static func < (lhs: PacketNumberSpace, rhs: PacketNumberSpace) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

@available(Network 0.1.0, *)
extension NetworkRigidArray {
    // This extension is used to subscript an array by a PacketNumberSpace's rawValue
    // This ensures the performance of the lookup in the data path
    package subscript<Index: RawRepresentable>(index: Index) -> Element where Index.RawValue == UInt8 {
        get {
            self[Int(index.rawValue)]
        }
        set {
            self[Int(index.rawValue)] = newValue
        }
    }
}

#endif
