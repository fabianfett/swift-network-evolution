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

/// The bytes of a datagram that QUIC parses and protects in place.
///
/// Mirrors the claim semantics of SwiftNetwork's `Frame`: bytes can be claimed from, and returned
/// to, the start and the end of the buffer, and only the unclaimed bytes in between are visible.
@available(Network 0.1.0, *)
package struct PacketBytes: ~Copyable, ~Escapable {
    package var storage: MutableSpan<UInt8>
    package private(set) var startOffset: Int
    package private(set) var endOffset: Int

    @_lifetime(copy storage)
    package init(_ storage: consuming MutableSpan<UInt8>, startOffset: Int = 0, endOffset: Int = 0) {
        precondition(startOffset >= 0 && endOffset >= 0 && startOffset + endOffset <= storage.count)
        self.storage = storage
        self.startOffset = startOffset
        self.endOffset = endOffset
    }

    package var unclaimedLength: Int {
        self.storage.count - (self.startOffset + self.endOffset)
    }

    package var bytes: RawSpan {
        @_lifetime(borrow self)
        get {
            self.storage.span.bytes.extracting(self.startOffset..<(self.storage.count - self.endOffset))
        }
    }

    package var mutableSpan: MutableSpan<UInt8> {
        @_lifetime(&self)
        mutating get {
            let range = self.startOffset..<(self.storage.count - self.endOffset)
            return self.storage._mutatingExtracting(range)
        }
    }

    package mutating func claim(fromStart: Int, fromEnd: Int = 0) -> Bool {
        let newStart = self.startOffset + fromStart
        let newEnd = self.endOffset + fromEnd
        guard newStart <= self.storage.count - newEnd else {
            let effectiveLength = self.storage.count
            outlinedProtoLogError(
                "Claiming bytes failed, start is beyond end; start, effective length, end",
                newStart,
                effectiveLength,
                newEnd
            )
            return false
        }
        self.startOffset = newStart
        self.endOffset = newEnd
        return true
    }

    package mutating func unclaim(fromStart: Int, fromEnd: Int = 0) -> Bool {
        guard fromStart <= self.startOffset else {
            let startOffset = self.startOffset
            outlinedProtoLogError("Frame cannot unclaim start bytes; requested, remaining", fromStart, startOffset)
            return false
        }
        guard fromEnd <= self.endOffset else {
            let endOffset = self.endOffset
            outlinedProtoLogError("Frame cannot unclaim end bytes; requested, remaining", fromEnd, endOffset)
            return false
        }
        self.startOffset -= fromStart
        self.endOffset -= fromEnd
        return true
    }
}

@available(Network 0.1.0, *)
extension Deserializer where Factory == EmptySpanFactory {
    package static func deserialize(
        _ packetBytes: inout PacketBytes,
        claim: Bool,
        _ builder: (_ buffer: inout Deserializer) throws(DeserializationError) -> Void
    ) -> DeserializationResult {
        let result = deserialize(packetBytes.bytes, builder)
        if claim, case .success(let parsedBytes, _) = result {
            guard packetBytes.claim(fromStart: parsedBytes) else {
                return .error(.bufferTooShort)
            }
        }
        return result
    }
}

@available(Network 0.1.0, *)
extension Serializer {
    package static func serialize(
        _ packetBytes: inout PacketBytes,
        claim: Bool,
        _ builder: (_ serializer: inout InPlaceSerializer<EmptySpanFactory>) throws(SerializationError) -> Void
    ) -> SerializationResult {
        let result = serialize(packetBytes.mutableSpan, builder)
        if claim, case .success(let writtenBytes, _) = result {
            guard packetBytes.claim(fromStart: writtenBytes) else {
                return .error(.bufferTooShort)
            }
        }
        return result
    }
}

/// Bytes that QUIC frames are parsed from and written into, with `Frame`'s claim semantics.
///
/// Both SwiftNetwork's `Frame` and `PacketBytes` conform, so the frame codec works for either.
@available(Network 0.1.0, *)
package protocol ClaimableBytes: ~Copyable, ~Escapable {
    var unclaimedLength: Int { get }
    mutating func claimBytes(fromStart: Int, fromEnd: Int) -> Bool
    mutating func unclaimBytes(fromStart: Int, fromEnd: Int) -> Bool
    /// Calls `body` with the unclaimed bytes, or returns `nil` if there are no bytes.
    func withUnclaimedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (RawSpan) throws(Failure) -> Result
    ) throws(Failure) -> Result?
    /// Calls `body` with the unclaimed bytes, or returns `nil` if there are no bytes.
    mutating func withUnclaimedMutableSpan<Result: ~Copyable, Failure: Error>(
        _ body: (inout MutableSpan<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result?
}

@available(Network 0.1.0, *)
extension PacketBytes: ClaimableBytes {
    package mutating func claimBytes(fromStart: Int, fromEnd: Int) -> Bool {
        self.claim(fromStart: fromStart, fromEnd: fromEnd)
    }

    package mutating func unclaimBytes(fromStart: Int, fromEnd: Int) -> Bool {
        self.unclaim(fromStart: fromStart, fromEnd: fromEnd)
    }

    package func withUnclaimedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (RawSpan) throws(Failure) -> Result
    ) throws(Failure) -> Result? {
        try body(self.bytes)
    }

    package mutating func withUnclaimedMutableSpan<Result: ~Copyable, Failure: Error>(
        _ body: (inout MutableSpan<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result? {
        var span = self.mutableSpan
        return try body(&span)
    }
}

@available(Network 0.1.0, *)
extension Deserializer where Factory == EmptySpanFactory {
    package static func deserialize(
        _ claimableBytes: inout some ClaimableBytes & ~Copyable & ~Escapable,
        claim: Bool,
        _ builder: (_ buffer: inout Deserializer) throws(DeserializationError) -> Void
    ) -> DeserializationResult {
        let result = claimableBytes.withUnclaimedBytes { bytes in deserialize(bytes, builder) } ?? .success
        if claim, case .success(let parsedBytes, _) = result {
            guard claimableBytes.claimBytes(fromStart: parsedBytes, fromEnd: 0) else {
                return .error(.bufferTooShort)
            }
        }
        return result
    }
}

@available(Network 0.1.0, *)
extension Serializer {
    package static func serialize(
        _ claimableBytes: inout some ClaimableBytes & ~Copyable & ~Escapable,
        claim: Bool,
        _ builder: (_ serializer: inout InPlaceSerializer<EmptySpanFactory>) throws(SerializationError) -> Void
    ) -> SerializationResult {
        let result =
            claimableBytes.withUnclaimedMutableSpan { span in
                var serializer = InPlaceSerializer<EmptySpanFactory>(span.mutableBytes)
                do {
                    try builder(&serializer)
                } catch {
                    // Error already recorded in internalResult via invalidate
                }
                return serializer.finalResult
            } ?? .success
        if claim, case .success(let writtenBytes, _) = result {
            guard claimableBytes.claimBytes(fromStart: writtenBytes, fromEnd: 0) else {
                return .error(.bufferTooShort)
            }
        }
        return result
    }
}
