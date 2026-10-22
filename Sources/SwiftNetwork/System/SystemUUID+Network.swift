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

#if canImport(Glibc)
import Glibc
#elseif canImport(Android)
import Android
#elseif canImport(Musl)
import Musl
#elseif canImport(Darwin)
import Darwin
#endif

// The parts of `SystemUUID` that need `NetworkError` or process-global state.
@available(Network 0.1.0, *)
extension SystemUUID {
    public init(_ span: Span<UInt8>) throws(NetworkError) {
        guard span.count == 16 else { throw NetworkError.posix(EINVAL) }
        var storage = UUIDStorage(repeating: 0x00)
        for i in 0..<16 {
            storage[i] = span[i]
        }
        self.init(storage)
    }

    static let insecureUUIDValue = NetworkMutex<UInt128>(0)
    static var nextInsecureUUIDValue: UInt128 {
        var value: UInt128 = 0
        insecureUUIDValue.withLock {
            if $0 == 0 || $0 == UInt128.max {
                $0 = UInt128.randomUUIDValue
            }
            value = $0
            $0 += 1
        }
        return value
    }

    public init(insecure: Bool = false) {
        var storage = UUIDStorage(repeating: 0x00)

        let uuidValueNumber: UInt128
        if insecure {
            uuidValueNumber = SystemUUID.nextInsecureUUIDValue
        } else {
            uuidValueNumber = UInt128.randomUUIDValue
        }
        for i in (0..<16).reversed() {
            let byte = UInt8((uuidValueNumber >> (i * 8)) & 0xFF)
            storage[i] = byte
        }

        self.init(storage)
    }
}

#if !NETWORK_STANDALONE
@available(Network 0.1.0, *)
extension SystemUUID: Codable {
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        let array = [UInt8](copying: self.span, maxCount: 16)
        try container.encode(array)
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let array = try container.decode(Array<UInt8>.self)
        self = try SystemUUID(array.span)
    }
}
#endif
