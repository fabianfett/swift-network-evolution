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

@available(Network 0.1.0, *)
extension Frame {
    /// Runs `body` with the frame's bytes as `PacketBytes`, then applies the claims `body` made back to
    /// the frame.
    ///
    /// Returns `nil` without running `body` if the frame has no bytes.
    mutating func withPacketBytes<Result: ~Copyable, Failure: Error>(
        _ body: (inout PacketBytes) throws(Failure) -> Result
    ) throws(Failure) -> Result? {
        let originalStart = self.startOffset
        let originalEnd = self.endOffset
        var newStart = originalStart
        var newEnd = originalEnd
        let result: Result
        do {
            guard let storage = self.fullMutableSpan else {
                return nil
            }
            var packetBytes = PacketBytes(storage, startOffset: originalStart, endOffset: originalEnd)
            defer {
                newStart = packetBytes.startOffset
                newEnd = packetBytes.endOffset
            }
            result = try body(&packetBytes)
        }
        self.applyClaims(fromStart: newStart - originalStart, fromEnd: newEnd - originalEnd)
        return result
    }

    private mutating func applyClaims(fromStart: Int, fromEnd: Int) {
        if fromStart > 0 {
            _ = self.claim(fromStart: fromStart)
        } else if fromStart < 0 {
            _ = self.unclaim(fromStart: -fromStart)
        }
        if fromEnd > 0 {
            _ = self.claim(fromStart: 0, fromEnd: fromEnd)
        } else if fromEnd < 0 {
            _ = self.unclaim(fromStart: 0, fromEnd: -fromEnd)
        }
    }

    /// All of the frame's bytes, ignoring claims.
    private var fullMutableSpan: MutableSpan<UInt8>? {
        @_lifetime(&self)
        mutating get {
            let length = self.effectiveBufferLength
            guard length > 0 else { return nil }
            var isBytes = false
            switch self.buffer {
            case .bytes: isBytes = true
            default: break
            }
            if isBytes {
                return self._bytes.mutableSpan._consumingExtracting(0..<length)
            }
            guard let unsafeBuffer = self.unsafeBuffer else {
                return nil
            }
            let bytes = UnsafeMutableRawBufferPointer(rebasing: unsafeBuffer[0..<length])
                .bindMemory(to: UInt8.self)
            return _overrideLifetime(bytes.mutableSpan, mutating: &self)
        }
    }
}

@available(Network 0.1.0, *)
extension Frame: ClaimableBytes {
    package mutating func claimBytes(fromStart: Int, fromEnd: Int) -> Bool {
        self.claim(fromStart: fromStart, fromEnd: fromEnd)
    }

    package mutating func unclaimBytes(fromStart: Int, fromEnd: Int) -> Bool {
        self.unclaim(fromStart: fromStart, fromEnd: fromEnd)
    }

    package func withUnclaimedBytes<Result: ~Copyable, Failure: Error>(
        _ body: (RawSpan) throws(Failure) -> Result
    ) throws(Failure) -> Result? {
        guard let bytes = self.bytes else {
            return nil
        }
        return try body(bytes)
    }

    package mutating func withUnclaimedMutableSpan<Result: ~Copyable, Failure: Error>(
        _ body: (inout MutableSpan<UInt8>) throws(Failure) -> Result
    ) throws(Failure) -> Result? {
        guard var span = self.mutableSpan else {
            return nil
        }
        return try body(&span)
    }
}
