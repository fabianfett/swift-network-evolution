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

#if compiler(<6.4)
// Swift 6.4 adds byte subscripts to the raw span types; earlier toolchains need these.

// Availability due to Swift's `RawSpan` type
@available(macOS 10.14.4, iOS 12.2, tvOS 12.2, watchOS 5.2, *)
extension RawSpan {
    @usableFromInline
    subscript(index: Int) -> UInt8 {
        unsafeLoad(fromByteOffset: index, as: UInt8.self)
    }
}

// Availability due to Swift's `MutableRawSpan` type
@available(macOS 10.14.4, iOS 12.2, tvOS 12.2, watchOS 5.2, *)
extension MutableRawSpan {
    @usableFromInline
    subscript(index: Int) -> UInt8 {
        get { unsafeLoad(fromByteOffset: index, as: UInt8.self) }
        set { storeBytes(of: newValue, toByteOffset: index, as: UInt8.self) }
    }
}
#endif
