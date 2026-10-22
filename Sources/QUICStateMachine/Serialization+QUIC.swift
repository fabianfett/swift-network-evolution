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

// QUIC-specific readers and writers for the span-based serializers.

@available(Network 0.1.0, *)
extension Deserializer where Factory: ~Escapable {
    package mutating func packetNumber(_ value: inout PacketNumber, pnSize: UInt8) throws(DeserializationError) {
        switch pnSize {
        case 1:
            // 1 byte
            var pn: UInt8 = 0
            try self.uint8(&pn)
            value = PacketNumber(Int64(pn))
        case 2:
            // 2 bytes
            var pn: UInt16 = 0
            try self.uint16NetworkByteOrder(&pn)
            value = PacketNumber(Int64(pn))
        case 3:
            // 3 bytes
            var high: UInt8 = 0
            var middle: UInt8 = 0
            var low: UInt8 = 0
            try self.uint8(&high)
            try self.uint8(&middle)
            try self.uint8(&low)
            let pn = UInt32(high) << 16 | UInt32(middle) << 8 | UInt32(low)
            value = PacketNumber(Int64(pn))
        case 4:
            // 4 bytes
            var pn: UInt32 = 0
            try self.uint32NetworkByteOrder(&pn)
            value = PacketNumber(Int64(pn))
        default:
            value = PacketNumber(-1)
            try invalidate(.validationFailed)
        }
    }

    public mutating func connectionID(
        _ value: inout QUICConnectionIDStorage,
        length: Int
    ) throws(DeserializationError) {
        guard length <= QUICConnectionID.maximumSize else {
            try invalidate(.parsingFailed)
        }
        var mutableBytes = value.mutableSpan
        try self.span(&mutableBytes, length: length)
    }
}

@available(Network 0.1.0, *)
extension InPlaceSerializer where Factory: ~Escapable, Factory: ~Copyable {

    package mutating func connectionID(_ value: QUICConnectionID) throws(SerializationError) {
        try self.uint8(UInt8(value.length))
        try self.buffer(value.connectionID)
    }

    package mutating func encodedPacketNumber(_ value: EncodedPacketNumber) throws(SerializationError) {
        let encodedSize = value.size.rawValue
        let offset = MemoryLayout<UInt64>.size - encodedSize

        try withUnsafeBytes(of: value.number.bigEndian) { bytes throws(SerializationError) in
            let sourcePtr = bytes.baseAddress!.advanced(by: offset)
            let bufferPtr = UnsafeBufferPointer(
                start: sourcePtr.assumingMemoryBound(to: UInt8.self),
                count: encodedSize
            )
            try self.span(bufferPtr.span.bytes)
        }
    }
}
