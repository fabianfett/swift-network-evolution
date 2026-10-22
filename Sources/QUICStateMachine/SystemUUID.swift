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

#if canImport(Synchronization)
internal import Synchronization
#endif

@_spi(Essentials)
@available(Network 0.1.0, *)
public struct SystemUUID: Hashable, Equatable, CustomStringConvertible, Sendable, BitwiseCopyable {

    package typealias UUIDStorage = [16 of UInt8]

    package let storage: UUIDStorage

    package init(_ storage: UUIDStorage) {
        self.storage = storage
    }

    static public let empty = SystemUUID(UUIDStorage(repeating: 0x00))

    static public func == (lhs: SystemUUID, rhs: SystemUUID) -> Bool {
        for i in 0..<lhs.storage.count {
            if lhs.storage[i] != rhs.storage[i] {
                return false
            }
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        for i in 0..<storage.count {
            hasher.combine(storage[i])
        }
    }

    public var span: Span<UInt8> {
        @_lifetime(borrow self)
        get {
            storage.span
        }
    }

    /// Returns a string representation of the UUID.
    ///
    /// For example, `E621E1F8-C36C-495A-93FC-0C247A3E6E5F`.
    public var description: String {
        var result = ""
        for i in 0..<storage.count {
            if i == 4 || i == 6 || i == 8 || i == 10 {
                result.append("-")
            }
            let string = String(storage[i], radix: 16, uppercase: true)
            if string.utf8.count == 1 {
                result.append("0")
            }
            result.append(string)
        }
        return result
    }

    public var uuidString: String {
        description
    }

    public var isUUIDNULL: Bool {
        self == Self.empty
    }
}

// Availability due to Swift's `UInt128.random(in:)` (introduced in Swift 6.0 / iOS 18 / macOS 15)
@available(macOS 15, iOS 18, tvOS 18, watchOS 11, *)
extension UInt128 {
    package static var randomUUIDValue: UInt128 {
        let random = UInt128.random(in: 1...UInt128.max)
        return random.withUUIDMaskApplied
    }

    package var withUUIDMaskApplied: UInt128 {
        let originalValue = self

        // Apply UUID version 4 format (byte 6) and variant (byte 8) directly on UInt128
        // Byte 6 is at bits 48-55 (from LSB): Clear upper 4 bits and set to 0x4
        let intermediateValue = (originalValue & ~(UInt128(0xF0) << 48)) | (UInt128(0x40) << 48)

        // Byte 8 is at bits 64-71 (from LSB): Clear upper 2 bits and set to 0b10
        return (intermediateValue & ~(UInt128(0xC0) << 64)) | (UInt128(0x80) << 64)
    }
}
