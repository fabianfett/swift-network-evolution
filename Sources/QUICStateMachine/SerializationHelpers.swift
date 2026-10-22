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

// MARK: - DeserializerSpanFactory

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public protocol DeserializerSpanFactory: ~Copyable, ~Escapable {
    /// Returns the next span from the factory.
    @_lifetime(&self)
    mutating func nextSpan() -> RawSpan?

    /// The total available byte count across all spans this factory can emit.
    var availableByteCount: Int { get }
}

/// A factory that stores no spans.
///
/// Use this factory when initializing a `Deserializer` directly from a `RawSpan`.
@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public struct EmptySpanFactory: ~Escapable, DeserializerSpanFactory {
    @_lifetime(immortal)
    package init() {}

    @_lifetime(&self)
    public mutating func nextSpan() -> RawSpan? {
        nil
    }

    public var availableByteCount: Int {
        0
    }
}

// `EmptySpanFactory` also serves as the placeholder factory for `InPlaceSerializer`
// when it is constructed directly from a single span, bypassing Span factories for the fast path.
@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
extension EmptySpanFactory: SerializerSpanFactory {
    @_lifetime(&self)
    public mutating func nextMutableSpan() -> MutableRawSpan? {
        nil
    }
}

// MARK: - SerializerSpanFactory

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public protocol SerializerSpanFactory: ~Copyable, ~Escapable {
    /// Returns the next mutable span from the factory.
    @_lifetime(&self)
    mutating func nextMutableSpan() -> MutableRawSpan?

    /// The total available byte count across all spans this factory can emit.
    var availableByteCount: Int { get }
}

/// A factory that stores a single mutable span.
///
/// Use this factory when initializing a `Serializer` directly from a `MutableRawSpan`.
@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public struct SingleMutableSpanFactory: ~Copyable, ~Escapable, SerializerSpanFactory {
    @usableFromInline
    package var span: MutableSpan<UInt8>
    private var consumed: Bool = false

    @inline(always)
    @inlinable
    @_lifetime(copy span)
    package init(_ span: consuming MutableSpan<UInt8>) {
        self.span = span
    }

    @_lifetime(&self)
    public mutating func nextMutableSpan() -> MutableRawSpan? {
        guard !consumed else { return nil }
        consumed = true
        return span.mutableBytes
    }

    public var availableByteCount: Int {
        span.count
    }
}
