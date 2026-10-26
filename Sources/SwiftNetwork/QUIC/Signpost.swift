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

#if SignpostOutput && canImport(os)

internal import os

@available(Network 0.1.0, *)
struct QUICSignpost {
    typealias IntervalState = OSSignpostIntervalState
    private static let signposter = OSSignposter(logger: Logger.proto)

    static func makeSignpostID() -> OSSignpostID {
        signposter.makeSignpostID()
    }

    static func disconnect(id: OSSignpostID) {
        signposter.emitEvent("disconnect", id: id)
    }

    static func outbound(id: OSSignpostID, length: Int) {
        signposter.emitEvent("outboundPacket", id: id, "\(length) bytes")
    }

    // Crypto signposts.
    static func sealBegin(keyState: String, packetNumber: PacketNumber) -> IntervalState {
        signposter.beginInterval("sealPacket", "\(keyState) #\(packetNumber)")
    }

    static func sealEnd(_ intervalState: IntervalState) {
        signposter.endInterval("sealPacket", intervalState)
    }

    static func openBegin(keyState: String, packetNumber: PacketNumber) -> IntervalState {
        signposter.beginInterval("openPacket", "\(keyState) #\(packetNumber)")
    }

    static func openEnd(_ intervalState: IntervalState) {
        signposter.endInterval("openPacket", intervalState)
    }
}
#else
// Signposts are not enabled unless the `SignpostOutput` package trait is
// enabled and the target platform supports Apple's OS signposting APIs.
@available(Network 0.1.0, *)
struct QUICSignpost {
    typealias IntervalState = Int
    static func makeSignpostID() -> Int { 0 }

    static func disconnect(id: Int) {}
    static func outbound(id: Int, length: Int) {}
    static func sealBegin(keyState: String, packetNumber: PacketNumber) -> IntervalState { 0 }
    static func sealEnd(_ intervalState: IntervalState) {}
    static func openBegin(keyState: String, packetNumber: PacketNumber) -> IntervalState { 0 }
    static func openEnd(_ intervalState: IntervalState) {}
}
#endif
#endif
