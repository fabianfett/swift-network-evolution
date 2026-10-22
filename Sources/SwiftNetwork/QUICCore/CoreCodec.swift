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

/// Reads QUIC wire values from a raw span.
///
/// Every read returns `nil` once the span runs out, and leaves the cursor where it was.
@available(Network 0.1.0, *)
struct CoreReader: ~Escapable {
    let bytes: RawSpan
    private(set) var offset: Int

    @_lifetime(copy bytes)
    init(_ bytes: RawSpan, offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    var remaining: Int {
        self.bytes.byteCount &- self.offset
    }

    var isAtEnd: Bool {
        self.offset >= self.bytes.byteCount
    }

    @inline(always)
    mutating func uint8() -> UInt8? {
        guard self.offset < self.bytes.byteCount else { return nil }
        let value = self.bytes.unsafeLoad(fromByteOffset: self.offset, as: UInt8.self)
        self.offset &+= 1
        return value
    }

    @inline(always)
    func peekUInt8() -> UInt8? {
        guard self.offset < self.bytes.byteCount else { return nil }
        return self.bytes.unsafeLoad(fromByteOffset: self.offset, as: UInt8.self)
    }

    mutating func uint32() -> UInt32? {
        guard self.remaining >= 4 else { return nil }
        var value: UInt32 = 0
        for i in 0..<4 {
            value = (value << 8) | UInt32(self.bytes.unsafeLoad(fromByteOffset: self.offset &+ i, as: UInt8.self))
        }
        self.offset &+= 4
        return value
    }

    mutating func uint64() -> UInt64? {
        guard self.remaining >= 8 else { return nil }
        var value: UInt64 = 0
        for i in 0..<8 {
            value = (value << 8) | UInt64(self.bytes.unsafeLoad(fromByteOffset: self.offset &+ i, as: UInt8.self))
        }
        self.offset &+= 8
        return value
    }

    /// Reads a variable-length integer (RFC 9000 Section 16).
    @inline(always)
    mutating func vle() -> UInt64? {
        guard let first = self.peekUInt8() else { return nil }
        let length = 1 << Int(first >> 6)
        guard self.remaining >= length else { return nil }
        var value = UInt64(first & 0x3f)
        for i in 1..<length {
            value = (value << 8) | UInt64(self.bytes.unsafeLoad(fromByteOffset: self.offset &+ i, as: UInt8.self))
        }
        self.offset &+= length
        return value
    }

    /// Returns the range of the next `length` bytes and skips them.
    mutating func range(_ length: Int) -> Range<Int>? {
        guard length >= 0, self.remaining >= length else { return nil }
        let start = self.offset
        self.offset &+= length
        return start..<self.offset
    }

    mutating func skip(_ length: Int) -> Bool {
        self.range(length) != nil
    }

    /// Reads `length` bytes into an array.
    mutating func array(_ length: Int) -> [UInt8]? {
        guard let range = self.range(length) else { return nil }
        return [UInt8](copying: self.bytes.extracting(range))
    }
}

/// Writes QUIC wire values into a mutable span.
///
/// Writes return `false`, and write nothing, once the span runs out.
@available(Network 0.1.0, *)
struct CoreWriter: ~Copyable, ~Escapable {
    var bytes: MutableSpan<UInt8>
    private(set) var offset: Int

    @_lifetime(copy bytes)
    init(_ bytes: consuming MutableSpan<UInt8>, offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    var remaining: Int {
        self.bytes.count &- self.offset
    }

    @inline(always)
    mutating func uint8(_ value: UInt8) -> Bool {
        guard self.offset < self.bytes.count else { return false }
        self.bytes[self.offset] = value
        self.offset &+= 1
        return true
    }

    mutating func uint16(_ value: UInt16) -> Bool {
        guard self.remaining >= 2 else { return false }
        self.bytes[self.offset] = UInt8(truncatingIfNeeded: value >> 8)
        self.bytes[self.offset &+ 1] = UInt8(truncatingIfNeeded: value)
        self.offset &+= 2
        return true
    }

    mutating func uint32(_ value: UInt32) -> Bool {
        guard self.remaining >= 4 else { return false }
        for i in 0..<4 {
            self.bytes[self.offset &+ i] = UInt8(truncatingIfNeeded: value >> (24 - 8 * i))
        }
        self.offset &+= 4
        return true
    }

    mutating func uint64(_ value: UInt64) -> Bool {
        guard self.remaining >= 8 else { return false }
        for i in 0..<8 {
            self.bytes[self.offset &+ i] = UInt8(truncatingIfNeeded: value >> (56 - 8 * i))
        }
        self.offset &+= 8
        return true
    }

    /// Writes a variable-length integer (RFC 9000 Section 16) in its shortest encoding.
    @inline(always)
    mutating func vle(_ value: UInt64) -> Bool {
        let length = CoreWriter.vleLength(value)
        guard self.remaining >= length else { return false }
        var remainingValue = value
        var index = self.offset &+ length &- 1
        while index > self.offset {
            self.bytes[index] = UInt8(truncatingIfNeeded: remainingValue)
            remainingValue >>= 8
            index &-= 1
        }
        let prefix: UInt8
        switch length {
        case 1: prefix = 0x00
        case 2: prefix = 0x40
        case 4: prefix = 0x80
        default: prefix = 0xc0
        }
        self.bytes[self.offset] = prefix | UInt8(truncatingIfNeeded: remainingValue)
        self.offset &+= length
        return true
    }

    /// Writes a variable-length integer with a fixed two byte encoding; `value` must be below 2^14.
    mutating func vle2(_ value: UInt16) -> Bool {
        precondition(value < (1 << 14))
        return self.uint16(0x4000 | value)
    }

    mutating func bytes(_ source: RawSpan) -> Bool {
        let count = source.byteCount
        guard self.remaining >= count else { return false }
        if count > 0 {
            let offset = self.offset
            self.bytes.withUnsafeMutableBufferPointer { destination in
                source.withUnsafeBytes { source in
                    UnsafeMutableRawBufferPointer(
                        UnsafeMutableBufferPointer(rebasing: destination[offset..<(offset &+ count)])
                    )
                    .copyMemory(from: source)
                }
            }
        }
        self.offset &+= count
        return true
    }

    mutating func zeros(_ count: Int) -> Bool {
        guard count >= 0, self.remaining >= count else { return false }
        if count > 0 {
            let offset = self.offset
            self.bytes.withUnsafeMutableBufferPointer { destination in
                UnsafeMutableBufferPointer(rebasing: destination[offset..<(offset &+ count)])
                    .update(repeating: 0)
            }
        }
        self.offset &+= count
        return true
    }

    @inline(always)
    static func vleLength(_ value: UInt64) -> Int {
        if value < (1 << 6) { return 1 }
        if value < (1 << 14) { return 2 }
        if value < (1 << 30) { return 4 }
        return 8
    }
}

/// A set of non-overlapping integer ranges, kept sorted in ascending order.
///
/// Tracks received packet numbers for acknowledgements, and received or acknowledged stream
/// offsets.
@available(Network 0.1.0, *)
struct CoreRangeSet {
    private(set) var ranges: [Range<UInt64>] = []

    var isEmpty: Bool { self.ranges.isEmpty }

    var count: Int { self.ranges.count }

    var lowerBound: UInt64? { self.ranges.first?.lowerBound }

    var upperBound: UInt64? { self.ranges.last?.upperBound }

    func contains(_ value: UInt64) -> Bool {
        // Most lookups are near the top.
        var index = self.ranges.count &- 1
        while index >= 0 {
            let range = self.ranges[index]
            if range.contains(value) { return true }
            if range.upperBound <= value { return false }
            index &-= 1
        }
        return false
    }

    /// Whether `range` is fully covered.
    func contains(_ range: Range<UInt64>) -> Bool {
        if range.isEmpty { return true }
        for existing in self.ranges where existing.lowerBound <= range.lowerBound {
            if existing.upperBound >= range.upperBound { return true }
        }
        return false
    }

    mutating func insert(_ value: UInt64) {
        self.insert(value..<(value &+ 1))
    }

    mutating func insert(_ range: Range<UInt64>) {
        guard !range.isEmpty else { return }
        // Fast path: appending at, or extending, the top.
        if let last = self.ranges.last {
            if range.lowerBound > last.upperBound {
                self.ranges.append(range)
                return
            }
            if range.lowerBound >= last.lowerBound {
                if range.upperBound > last.upperBound {
                    self.ranges[self.ranges.count &- 1] = last.lowerBound..<range.upperBound
                }
                return
            }
        } else {
            self.ranges.append(range)
            return
        }
        var newLower = range.lowerBound
        var newUpper = range.upperBound
        var result: [Range<UInt64>] = []
        result.reserveCapacity(self.ranges.count &+ 1)
        var inserted = false
        for existing in self.ranges {
            if existing.upperBound < newLower {
                result.append(existing)
            } else if existing.lowerBound > newUpper {
                if !inserted {
                    result.append(newLower..<newUpper)
                    inserted = true
                }
                result.append(existing)
            } else {
                newLower = min(newLower, existing.lowerBound)
                newUpper = max(newUpper, existing.upperBound)
            }
        }
        if !inserted {
            result.append(newLower..<newUpper)
        }
        self.ranges = result
    }

    /// Removes everything below `value`.
    mutating func removeAll(below value: UInt64) {
        while let first = self.ranges.first, first.lowerBound < value {
            if first.upperBound <= value {
                self.ranges.removeFirst()
            } else {
                self.ranges[0] = value..<first.upperBound
                break
            }
        }
    }

    /// Drops the lowest ranges until at most `maximumCount` remain.
    mutating func trim(toCount maximumCount: Int) {
        if self.ranges.count > maximumCount {
            self.ranges.removeFirst(self.ranges.count &- maximumCount)
        }
    }

    mutating func removeAll() {
        self.ranges.removeAll(keepingCapacity: true)
    }
}

#endif
