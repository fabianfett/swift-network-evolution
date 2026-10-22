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

#if !NETWORK_EMBEDDED && canImport(Foundation)
import Foundation
#endif

#if canImport(BasicContainers)
import BasicContainers
#endif

// `Frame` and `FrameArray` entry points for the span-based serializers in `QUICStateMachine`.

#if !NETWORK_EMBEDDED

// MARK: - FrameArraySpanFactory

/// A span factory that walks the frames in a frame array.
///
/// Provides each frame's bytes as a span and optionally claims consumed bytes from each frame.
/// Walks the frames in a `FrameArray`.
@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public struct FrameArraySpanFactory: ~Copyable, ~Escapable, DeserializerSpanFactory {
    private var frameArray: FrameArray
    private var spanIndex = 0
    private var spanCount: Int
    public private(set) var availableByteCount: Int

    /// Extracts the frame array from the factory, consuming the factory in the process.
    @usableFromInline
    consuming func takeFrameArray() -> FrameArray {
        frameArray
    }

    public mutating func drainArray(maximumByteCount: Int) -> FrameArray {
        let removedFrames = frameArray.drainArray(maximumByteCount: maximumByteCount)

        // Reset internal counters
        spanCount = frameArray.count
        availableByteCount = frameArray.unclaimedLength
        spanIndex = 0

        return removedFrames
    }

    // The factory owns the FrameArray (consumed in), so it has no external
    // lifetime dependency. @_lifetime(immortal) is correct for a self-contained
    // ~Escapable type whose data is fully owned.
    @_lifetime(immortal)
    @usableFromInline
    init(_ frameArray: consuming FrameArray) {
        self.spanCount = frameArray.count
        self.availableByteCount = frameArray.unclaimedLength
        self.frameArray = frameArray
    }

    @_lifetime(&self)
    public mutating func nextSpan() -> RawSpan? {
        // Check if we're out of spans
        guard spanIndex < spanCount else {
            return nil
        }

        let currentIndex = spanIndex

        // Advance to the next span
        spanIndex += 1

        return _overrideLifetime(frameArray.bytes(at: currentIndex), borrowing: self)
    }
}

#endif

@available(Network 0.1.0, *)
extension Deserializer where Factory: ~Copyable, Factory: ~Escapable {
    @_optimize(speed)
    @inlinable
    @inline(always)
    public static func deserialize(
        _ frame: inout Frame,
        claim: Bool,
        _ builder: (_ buffer: inout Deserializer) throws(DeserializationError) -> Void
    ) -> DeserializationResult where Factory == EmptySpanFactory {
        var result: DeserializationResult = .success
        if let bytes = frame.bytes {
            result = deserialize(bytes, builder)
        }
        if claim, case .success(let parsedBytes, _) = result {
            guard frame.claim(fromStart: parsedBytes) else {
                return .error(.bufferTooShort)
            }
        }
        return result
    }

    #if !NETWORK_EMBEDDED
    @_optimize(speed)
    @inlinable
    @inline(always)
    public static func deserialize(
        _ frameArray: inout FrameArray,
        claim: Bool,
        removeClaimedFrames: Bool,
        _ builder: (_ buffer: inout Deserializer<FrameArraySpanFactory>) throws(DeserializationError) -> Void
    ) -> DeserializationResult where Factory == FrameArraySpanFactory {
        guard frameArray.count > 0 else {
            return .error(.bufferTooShort)
        }

        var factory = FrameArraySpanFactory(consume frameArray)
        let result = deserialize(&factory, builder)
        frameArray = factory.takeFrameArray()

        if claim, case .success(let parsedBytes, _) = result {
            guard frameArray.claim(fromStart: parsedBytes, removeClaimedFrames: removeClaimedFrames) else {
                return .error(.bufferTooShort)
            }
        }

        return result
    }
    #endif
}

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public struct FrameSerializer: ~Copyable {
    private var currentBuffer: NetworkUniqueArray<UInt8>? = nil
    private var cursor = 0
    private var currentBufferByteCount = 0

    private var frameArray = FrameArray()
    private let capacity: Int
    private var internalResult: SerializationResult = .success

    private mutating func convertBufferToFrame() {
        cursor = 0
        currentBufferByteCount = 0
        if currentBuffer != nil {
            var swapBuffer: NetworkUniqueArray<UInt8>?
            swapBuffer = nil
            swap(&swapBuffer, &currentBuffer)
            frameArray.add(frame: .init(bytes: swapBuffer!))
        }
    }

    /// Extracts the frame array from the serializer, consuming the serializer in the process.
    fileprivate consuming func extractFrames() -> FrameArray {
        convertBufferToFrame()
        return frameArray
    }

    private mutating func addFrame(_ frame: consuming Frame) {
        convertBufferToFrame()
        frameArray.add(frame: frame)
    }

    private mutating func withOutputSpan(length: Int, _ body: (inout OutputRawSpan) -> Void) {
        if currentBuffer == nil {
            currentBuffer = .init(minimumCapacity: capacity)
            currentBufferByteCount = capacity
            cursor = 0
        }

        currentBuffer?.append(addingCount: length) { outputSpan in
            outputSpan.append(repeating: 0, count: length)
            var mutableSpan = outputSpan.mutableSpan
            var mutableBytes = mutableSpan.mutableBytes
            mutableBytes.withUnsafeMutableBytes { buffer in
                var outputRawSpan = OutputRawSpan(buffer: buffer, initializedCount: 0)
                body(&outputRawSpan)
                cursor = outputRawSpan.byteCount
            }
        }
    }

    private var remaining: Int {
        #if DEBUG
        precondition(currentBufferByteCount >= cursor)
        #endif
        return currentBufferByteCount - cursor
    }

    init(capacity: Int) {
        self.capacity = capacity
    }

    /// Writes a fixed-size value into an output span.
    private mutating func writeFixedSize<T: BitwiseCopyable>(_ value: T) {
        withOutputSpan(length: MemoryLayout<T>.size) { outputSpan in
            outputSpan.append(value, as: T.self)
        }
    }

    public mutating func uint8(_ value: UInt8) {
        writeFixedSize(value)
    }

    public mutating func uint16(_ value: UInt16) {
        writeFixedSize(value)
    }

    public mutating func int16(_ value: Int16) {
        writeFixedSize(value)
    }

    public mutating func uint32(_ value: UInt32) {
        writeFixedSize(value)
    }

    public mutating func int32(_ value: Int32) {
        writeFixedSize(value)
    }

    public mutating func uint64(_ value: UInt64) {
        writeFixedSize(value)
    }

    public mutating func uint16NetworkByteOrder(_ value: UInt16) {
        writeFixedSize(value.bigEndian)
    }

    public mutating func uint32NetworkByteOrder(_ value: UInt32) {
        writeFixedSize(value.bigEndian)
    }

    public mutating func uint64NetworkByteOrder(_ value: UInt64) {
        writeFixedSize(value.bigEndian)
    }

    public mutating func vle<T: FixedWidthInteger>(_ value: T) {
        self.vle(UInt64(value))
    }

    public mutating func vle(_ value: UInt64) {
        var value = value
        let length: Int
        if let fitLength = value.safeVariableLengthSize {
            length = fitLength
        } else {
            // Too big, encode the max UInt62 value instead
            value = UInt64(4_611_686_018_427_387_903)
            length = 8
        }

        withOutputSpan(length: length) { outputSpan in
            switch length {
            case 1:
                outputSpan.append(UInt8(value), as: UInt8.self)
            case 2:
                outputSpan.append(UInt16(1 << 14 | value).bigEndian, as: UInt16.self)
            case 4:
                outputSpan.append(UInt32(1 << 31 | value).bigEndian, as: UInt32.self)
            default:
                outputSpan.append(UInt64(3 << 62 | value).bigEndian, as: UInt64.self)
            }
        }
    }

    public mutating func uuid(_ value: SystemUUID) {
        writeFixedSize(value)
    }

    mutating public func fixedLengthUTF8(_ value: String, byteCount: Int) {
        guard byteCount > 0 else {
            return
        }

        #if os(watchOS) && (arch(arm64_32) || arch(arm))
        // Fix for Span not being available on 32-bit watchOS
        // This surfaces when build with the arm64_32 toolchain
        // https://github.com/swiftlang/swift/blob/51b0b4aa41f28eae7d96af6f98c1fbd2b4b63958/stdlib/public/core/StringUTF8View.swift#L386
        let utf8Bytes = Array(value.utf8).span.bytes.extracting(first: byteCount)
        #else
        // Builds for watchOS 64 bit variants and all other platforms
        let utf8Bytes = value.utf8.span.bytes.extracting(first: byteCount)
        #endif
        let extraBytes = byteCount - utf8Bytes.byteCount

        withOutputSpan(length: byteCount) { outputSpan in
            outputSpan.withUnsafeMutableBytes { mutableBuffer, _ in
                utf8Bytes.withUnsafeBytes { utf8Buffer in
                    mutableBuffer.copyMemory(from: utf8Buffer)
                }
            }
            if extraBytes > 0 {
                // Pad with zeros
                outputSpan.append(repeating: 0, count: extraBytes, as: UInt8.self)
            }
        }
    }

    public mutating func string(_ value: String) {
        let utf8 = value.utf8
        uint16(UInt16(utf8.count))
        fixedLengthUTF8(value, byteCount: utf8.count)
    }

    public mutating func span(_ value: RawSpan) {
        withOutputSpan(length: value.byteCount) { outputSpan in
            outputSpan.withUnsafeMutableBytes { toBuffer, _ in
                value.withUnsafeBytes { fromBuffer in
                    toBuffer.copyMemory(from: fromBuffer)
                }
            }
        }
    }

    public mutating func buffer(_ value: [UInt8]) {
        span(value.span.bytes)
    }

    public mutating func frame(_ frame: inout Frame) {
        addFrame(frame)
        frame = .init()
    }

    public mutating func frameArray(_ frames: inout FrameArray) {
        while let frame = frames.popFirst() {
            addFrame(frame)
        }
    }

    public mutating func frameArray(_ frames: inout FrameArray?) {
        while let frame = frames?.popFirst() {
            addFrame(frame)
        }
    }

    #if !NETWORK_EMBEDDED && canImport(Foundation)
    public mutating func buffer(_ value: any DataProtocol) {
        let array = [UInt8](value)
        span(array.span.bytes)
    }
    #endif
}

@available(Network 0.1.0, *)
extension Serializer {
    @inline(always)
    @inlinable
    public static func serialize(
        _ frame: inout Frame,
        claim: Bool,
        _ builder: (_ serializer: inout InPlaceSerializer<EmptySpanFactory>) throws(SerializationError) -> Void
    ) -> SerializationResult {

        var result: SerializationResult = .success
        if let mutableBytes = frame.mutableSpan {
            result = serialize(mutableBytes, builder)
        }
        if claim, case .success(let writtenBytes, _) = result {
            guard frame.claim(fromStart: writtenBytes) else {
                return .error(.bufferTooShort)
            }
        }
        return result
    }

    public static func serialize(frameCapacity: Int, _ builder: (_ buffer: inout FrameSerializer) -> Void) -> FrameArray
    {
        var serializer = FrameSerializer(capacity: frameCapacity)
        _ = builder(&serializer)
        return serializer.extractFrames()
    }
}
