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

// `Protector` seals and opens packets in place in a span. These adapters protect the bytes of a `Frame`.
@available(Network 0.1.0, *)
extension Protector {
    mutating func seal(_ packet: inout Packet, frame: inout Frame) throws(QUICError) {
        guard var buffer = frame.mutableSpan else {
            throw QUICError.protector(SecFramerError.sealingFailed)
        }
        try self.seal(&packet, buffer: &buffer)
    }

    func openHeader(_ packet: inout Packet, frame: inout Frame) throws(QUICError) {
        guard var buffer = frame.mutableSpan else {
            throw QUICError.protector(SecFramerError.openFailed)
        }
        try self.openHeader(&packet, buffer: &buffer)
    }

    func open(_ packet: inout Packet, frame: inout Frame) throws(QUICError) {
        guard var buffer = frame.mutableSpan else {
            self.log.error("Unclaimed bytes nil")
            throw QUICError.protector(SecFramerError.openFailed)
        }
        try self.open(&packet, buffer: &buffer)
    }
}
