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

import XCTest

@_spi(Essentials) @_spi(ProtocolProvider) @testable import SwiftNetwork

#if IMPORT_CRYPTO && !NETWORK_NO_SWIFT_QUIC && DEBUG

/// Path validation and connection migration (RFC 9000 Sections 8.2 and 9) in `QUICConnectionCore`.
@available(Network 0.1.0, *)
final class QUICConnectionCoreMigrationTests: XCTestCase {
    private static let newPath = CorePathID(1)

    private static func configuration(automaticallyIssueConnectionIDs: Bool = true) -> QUICConnectionCore.Configuration
    {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.automaticallyIssueConnectionIDs = automaticallyIssueConnectionIDs
        configuration.activeConnectionIDLimit = 4
        return configuration
    }

    private static func connectedPair(
        client: QUICConnectionCore.Configuration = configuration(),
        server: QUICConnectionCore.Configuration = configuration()
    ) -> LockstepPair {
        var pair = LockstepPair(clientConfiguration: client, serverConfiguration: server)
        pair.exchange()
        // Confirms the handshake on the client and hands out the connection IDs.
        pair.exchange()
        pair.clientEvents.removeAll()
        pair.serverEvents.removeAll()
        return pair
    }

    /// A datagram and the path it went out or arrived on.
    private struct Routed {
        var path: CorePathID
        var bytes: [UInt8]
    }

    /// Everything `machine` has to send: the active path's datagrams and the probes for others.
    private static func drain(_ machine: inout QUICConnectionCore, now: NetworkClock.Instant) -> [Routed] {
        var datagrams: [Routed] = []
        var buffer = [UInt8](repeating: 0, count: 1500)
        while datagrams.count < 1000 {
            let path = machine.pathWithProbeToSend ?? machine.activePathID
            var span = buffer.mutableSpan
            guard let length = machine.send(into: &span, on: path, now: now) else { break }
            datagrams.append(Routed(path: path, bytes: Array(buffer[0..<length])))
        }
        return datagrams
    }

    /// Exchanges datagrams until both sides are quiet. `route` maps the path a datagram went out on
    /// to the one it arrives on at the other side, or drops it with `nil`.
    private static func exchange(
        _ pair: inout LockstepPair,
        rounds: Int = 20,
        route: (_ toServer: Bool, _ path: CorePathID) -> CorePathID? = { _, path in path },
        sent: (_ toServer: Bool, _ datagram: Routed) -> Void = { _, _ in }
    ) {
        for _ in 0..<rounds {
            let fromClient = Self.drain(&pair.client, now: pair.now)
            guard var server = pair.server.take() else { return }
            for var datagram in fromClient {
                sent(true, datagram)
                guard let path = route(true, datagram.path) else { continue }
                var span = datagram.bytes.mutableSpan
                server.receive(&span, on: path, now: pair.now)
            }
            pair.serverEvents += LockstepPair.events(&server)
            let fromServer = Self.drain(&server, now: pair.now)
            pair.server = consume server
            for var datagram in fromServer {
                sent(false, datagram)
                guard let path = route(false, datagram.path) else { continue }
                var span = datagram.bytes.mutableSpan
                pair.client.receive(&span, on: path, now: pair.now)
            }
            pair.clientEvents += LockstepPair.events(&pair.client)
            if fromClient.isEmpty && fromServer.isEmpty { return }
        }
    }

    private static func validated(_ events: [QUICConnectionCore.Event]) -> [CorePathID] {
        events.compactMap {
            if case .pathValidated(let path) = $0 { return path }
            return nil
        }
    }

    private static func failed(_ events: [QUICConnectionCore.Event]) -> [CorePathID] {
        events.compactMap {
            if case .pathFailed(let path) = $0 { return path }
            return nil
        }
    }

    private static func activeChanges(_ events: [QUICConnectionCore.Event]) -> [CorePathID] {
        events.compactMap {
            if case .activePathChanged(let path) = $0 { return path }
            return nil
        }
    }

    /// The destination connection ID of a short header datagram.
    private static func destination(_ datagram: [UInt8]) -> [UInt8]? {
        guard datagram[0] & 0x80 == 0 else { return nil }
        return Array(datagram[1..<9])
    }

    private static func sendAndReceive(_ pair: inout LockstepPair, _ payload: [UInt8]) throws -> [UInt8] {
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write(payload.span.bytes, to: streamID, fin: true)
        Self.exchange(&pair)
        guard var server = pair.server.take() else {
            XCTFail("No server")
            return []
        }
        var received: [UInt8] = []
        while let progress: Int = server.read(
            from: streamID,
            { bytes, _ in
                received += bytes.withUnsafeBytes { Array($0) }
                return (bytes.byteCount, bytes.byteCount)
            }
        ), progress > 0 {}
        pair.server = consume server
        return received
    }

    func testTheClientMigratesOnceThePathIsValidated() throws {
        var pair = Self.connectedPair()
        let oldDestination = try XCTUnwrap(pair.client.peerConnectionID(on: .initial))
        XCTAssertTrue(pair.client.migrate(to: Self.newPath, now: pair.now))
        // Not before the PATH_RESPONSE.
        XCTAssertEqual(pair.client.activePathID, .initial)
        let newDestination = try XCTUnwrap(pair.client.peerConnectionID(on: Self.newPath))
        XCTAssertNotEqual(newDestination, oldDestination, "a new path takes a new connection ID")

        var onNewPath: [[UInt8]] = []
        Self.exchange(
            &pair,
            sent: { toServer, datagram in
                if toServer && datagram.path == Self.newPath { onNewPath.append(datagram.bytes) }
            }
        )
        XCTAssertEqual(Self.validated(pair.clientEvents), [Self.newPath])
        XCTAssertEqual(Self.activeChanges(pair.clientEvents), [Self.newPath])
        XCTAssertEqual(pair.client.activePathID, Self.newPath)
        XCTAssertTrue(pair.client.isPathValidated(Self.newPath))
        // The server follows the PING after the migration and validates the path in turn.
        XCTAssertEqual(Self.activeChanges(pair.serverEvents), [Self.newPath])
        XCTAssertEqual(Self.validated(pair.serverEvents), [Self.newPath])
        XCTAssertEqual(pair.server?.activePathID, Self.newPath)
        XCTAssertFalse(onNewPath.isEmpty)
        for datagram in onNewPath {
            XCTAssertEqual(Self.destination(datagram), newDestination.connectionID)
        }

        // Data flows on the new path, and none goes out on the old one.
        var sentOnOldPath = 0
        let payload = [UInt8](repeating: 7, count: 4000)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write(payload.span.bytes, to: streamID, fin: true)
        Self.exchange(
            &pair,
            sent: { _, datagram in
                if datagram.path == .initial { sentOnOldPath += 1 }
            }
        )
        XCTAssertEqual(sentOnOldPath, 0)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        var received = 0
        while let progress: Int = server.read(
            from: streamID,
            { bytes, _ in
                received += bytes.byteCount
                return (bytes.byteCount, bytes.byteCount)
            }
        ), progress > 0 {}
        pair.server = consume server
        XCTAssertEqual(received, payload.count)
    }

    /// RFC 9000 Section 8.2.1-8.2.2: PATH_CHALLENGE and PATH_RESPONSE go out in datagrams of at
    /// least 1200 bytes, unless the anti-amplification limit says otherwise.
    func testProbesArePaddedTo1200Bytes() {
        var pair = Self.connectedPair()
        let serverDestination = pair.server?.peerConnectionID(on: .initial)
        XCTAssertTrue(pair.client.probePath(Self.newPath, now: pair.now))
        var sizes: [Int] = []
        Self.exchange(
            &pair,
            sent: { _, datagram in
                if datagram.path == Self.newPath { sizes.append(datagram.bytes.count) }
            }
        )
        XCTAssertEqual(Self.validated(pair.clientEvents), [Self.newPath])
        // Probing alone doesn't migrate.
        XCTAssertEqual(pair.client.activePathID, .initial)
        XCTAssertEqual(pair.server?.activePathID, .initial)
        XCTAssertTrue(Self.activeChanges(pair.serverEvents).isEmpty, "the server followed a probe")
        // A new connection ID on another path is no reason to change the one of the active path.
        XCTAssertEqual(pair.server?.peerConnectionID(on: .initial), serverDestination)
        // The client's challenge, the server's response and challenge, the client's response.
        XCTAssertGreaterThanOrEqual(sizes.count, 3)
        for size in sizes {
            XCTAssertGreaterThanOrEqual(size, 1200)
        }
    }

    /// RFC 9000 Section 9.3: a server follows a client whose address changed under it, and
    /// validates the new address.
    func testTheServerFollowsANATRebinding() throws {
        var pair = Self.connectedPair()
        // The client keeps sending on its path, which the server sees as a new one. The server's old
        // path is gone.
        let route: (Bool, CorePathID) -> CorePathID? = { toServer, path in
            if toServer { return path == .initial ? Self.newPath : nil }
            return path == Self.newPath ? .initial : nil
        }
        pair.client.injectedFrames.append([0x01])
        var clientSizes: [Int] = []
        Self.exchange(
            &pair,
            route: route,
            sent: { toServer, datagram in
                if toServer { clientSizes.append(datagram.bytes.count) }
            }
        )
        XCTAssertEqual(pair.server?.activePathID, Self.newPath)
        XCTAssertEqual(Self.activeChanges(pair.serverEvents), [Self.newPath])
        // The client answers on its path, the active one, in a full-size datagram (RFC 9000
        // Section 8.2.2).
        XCTAssertTrue(clientSizes.contains { $0 >= 1200 }, "\(clientSizes)")
        XCTAssertEqual(Self.validated(pair.serverEvents), [Self.newPath])
        XCTAssertEqual(pair.client.activePathID, .initial)
        XCTAssertTrue(Self.activeChanges(pair.clientEvents).isEmpty)

        let payload = Array("after the rebinding".utf8)
        XCTAssertEqual(try Self.sendAndReceive(&pair, payload), payload)
    }

    /// A client moves to a path it validated before right away, and its PING tells the server.
    func testMigratingToAProbedPathNeedsNoNewValidation() {
        var pair = Self.connectedPair()
        XCTAssertTrue(pair.client.probePath(Self.newPath, now: pair.now))
        Self.exchange(&pair)
        XCTAssertTrue(pair.client.isPathValidated(Self.newPath))
        XCTAssertEqual(pair.server?.activePathID, .initial)
        pair.clientEvents.removeAll()
        pair.serverEvents.removeAll()
        // Whatever else the client had to send went out on the old path.
        _ = Self.drain(&pair.client, now: pair.now)

        XCTAssertTrue(pair.client.migrate(to: Self.newPath, now: pair.now))
        XCTAssertEqual(pair.client.activePathID, Self.newPath)
        XCTAssertNil(pair.client.pathWithProbeToSend)
        XCTAssertEqual(pair.client.paths[Self.newPath]?.isValidating, false, "validated again")
        Self.exchange(&pair)
        XCTAssertEqual(Self.activeChanges(pair.clientEvents), [Self.newPath])
        XCTAssertEqual(Self.activeChanges(pair.serverEvents), [Self.newPath])
        XCTAssertEqual(pair.server?.activePathID, Self.newPath)
    }

    /// RFC 9000 Section 9.5: without a spare connection ID of the client, the server keeps the one
    /// it has for the new address.
    func testANATRebindingWithoutSpareConnectionIDsKeepsTheCurrentOne() throws {
        var pair = Self.connectedPair(client: Self.configuration(automaticallyIssueConnectionIDs: false))
        let destination = pair.server?.peerConnectionID(on: .initial)
        let route: (Bool, CorePathID) -> CorePathID? = { toServer, path in
            if toServer { return path == .initial ? Self.newPath : nil }
            return path == Self.newPath ? .initial : nil
        }
        pair.client.injectedFrames.append([0x01])
        Self.exchange(&pair, route: route)
        XCTAssertEqual(pair.server?.activePathID, Self.newPath)
        XCTAssertEqual(pair.server?.peerConnectionID(on: Self.newPath), destination)
        XCTAssertEqual(Self.validated(pair.serverEvents), [Self.newPath])
    }

    /// RFC 9000 Section 9.3: until the new address is validated, the server sends at most three
    /// times what arrived from it.
    func testTheServerLimitsWhatItSendsToAnUnvalidatedAddress() throws {
        var pair = Self.connectedPair()
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 1, count: 100).span.bytes, to: streamID)
        // Nothing the server sends to the new address arrives, so the address is never validated.
        let route: (Bool, CorePathID) -> CorePathID? = { toServer, path in
            toServer ? (path == .initial ? Self.newPath : nil) : nil
        }
        Self.exchange(&pair, rounds: 1, route: route)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(server.activePathID, Self.newPath)
        // A response that would go beyond the limit.
        server.write([UInt8](repeating: 2, count: 20_000).span.bytes, to: streamID)
        _ = Self.drain(&server, now: pair.now)
        let state = try XCTUnwrap(server.paths[Self.newPath])
        XCTAssertFalse(state.isValidated)
        XCTAssertGreaterThan(state.bytesSent, 0)
        XCTAssertLessThanOrEqual(state.bytesSent, 3 * state.bytesReceived)
        pair.server = consume server
    }

    /// RFC 9000 Section 8.2.4: a path whose challenges go unanswered fails; the connection stays on
    /// the path it has.
    func testAPathFailsAfterUnansweredChallenges() throws {
        var pair = Self.connectedPair()
        XCTAssertTrue(pair.client.migrate(to: Self.newPath, now: pair.now))
        let route: (Bool, CorePathID) -> CorePathID? = { _, path in path == Self.newPath ? nil : path }
        Self.exchange(&pair, route: route)
        for _ in 0..<10 where Self.failed(pair.clientEvents).isEmpty {
            pair.advanceToNextDeadline()
            Self.exchange(&pair, route: route)
        }
        XCTAssertEqual(Self.failed(pair.clientEvents), [Self.newPath])
        XCTAssertEqual(pair.client.paths[Self.newPath]?.challengesSent, CorePath.maximumChallenges)
        XCTAssertEqual(pair.client.activePathID, .initial)
        XCTAssertTrue(Self.activeChanges(pair.clientEvents).isEmpty)
        XCTAssertFalse(pair.client.isClosingOrDraining)

        let payload = Array("still on the first path".utf8)
        XCTAssertEqual(try Self.sendAndReceive(&pair, payload), payload)
    }

    /// RFC 9000 Section 9: a client doesn't migrate if the server disabled it.
    func testDisableActiveMigrationRefusesMigration() {
        var server = Self.configuration()
        server.disableActiveMigration = true
        var pair = Self.connectedPair(server: server)
        XCTAssertFalse(pair.client.migrate(to: Self.newPath, now: pair.now))
        XCTAssertEqual(pair.client.activePathID, .initial)
        XCTAssertNil(pair.client.pathWithProbeToSend)
    }

    /// RFC 9000 Section 9.5: a client needs an unused connection ID of the server to probe.
    func testMigrationNeedsASpareConnectionID() {
        var pair = Self.connectedPair(server: Self.configuration(automaticallyIssueConnectionIDs: false))
        XCTAssertFalse(pair.client.migrate(to: Self.newPath, now: pair.now))
        XCTAssertNil(pair.client.pathWithProbeToSend)
    }

    /// Forgetting the old path retires the connection ID it used.
    func testForgettingAPathRetiresItsConnectionID() throws {
        var pair = Self.connectedPair()
        let oldDestination = try XCTUnwrap(pair.client.peerConnectionID(on: .initial))
        XCTAssertTrue(pair.client.migrate(to: Self.newPath, now: pair.now))
        Self.exchange(&pair)
        XCTAssertEqual(pair.client.activePathID, Self.newPath)
        XCTAssertEqual(pair.client.peerConnectionID(on: .initial), oldDestination)
        pair.client.forgetPath(.initial)
        XCTAssertNil(pair.client.paths[.initial])
        Self.exchange(&pair)
        let retired = pair.clientEvents.compactMap {
            if case .retiredPeerConnectionID(let connectionID, _) = $0 { return connectionID }
            return nil
        }
        XCTAssertEqual(retired, [oldDestination])
        let retiredByServer = pair.serverEvents.compactMap {
            if case .retiredLocalConnectionID(let connectionID) = $0 { return connectionID }
            return nil
        }
        XCTAssertEqual(retiredByServer, [oldDestination])
    }

    /// RFC 9000 Section 5.1.2: Retire Prior To takes the connection ID of a path, too, which gets
    /// another one.
    func testRetirePriorToReplacesTheConnectionIDOfAPath() throws {
        var pair = Self.connectedPair()
        XCTAssertTrue(pair.client.probePath(Self.newPath, now: pair.now))
        let probing = try XCTUnwrap(pair.client.paths[Self.newPath]?.peerConnectionIDSequenceNumber)
        XCTAssertEqual(probing, 1)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        let connectionID = QUICConnectionID(8)
        server.injectedFrames.append(
            [0x18, 8, 2, UInt8(connectionID.length)] + connectionID.connectionID + QUICStatelessResetToken().token
        )
        var fromServer = LockstepPair.drain(&server, now: pair.now)
        pair.server = consume server
        for index in fromServer.indices {
            var span = fromServer[index].mutableSpan
            pair.client.receive(&span, now: pair.now)
        }
        XCTAssertNil(pair.client.paths[Self.newPath]?.peerConnectionIDSequenceNumber)
        XCTAssertNotNil(pair.client.pathWithProbeToSend)
        Self.exchange(&pair)
        let replacement = try XCTUnwrap(pair.client.paths[Self.newPath]?.peerConnectionIDSequenceNumber)
        XCTAssertGreaterThanOrEqual(replacement, 2)
        XCTAssertEqual(Self.validated(pair.clientEvents), [Self.newPath])
    }

    /// A flood of PATH_CHALLENGE frames doesn't grow the responses without bound.
    func testPathChallengeResponsesAreBounded() throws {
        var pair = Self.connectedPair()
        for index in 0..<20 {
            pair.client.injectedFrames.append([0x1a] + [UInt8](repeating: UInt8(index), count: 8))
        }
        var fromClient = Self.drain(&pair.client, now: pair.now)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        for index in fromClient.indices {
            var span = fromClient[index].bytes.mutableSpan
            server.receive(&span, now: pair.now)
        }
        XCTAssertEqual(server.paths[.initial]?.pendingResponses.count, CorePath.maximumPendingResponses)
        XCTAssertEqual(server.paths[.initial]?.pendingResponses.last, 0x1313_1313_1313_1313)
        pair.server = consume server
    }
}

#endif
