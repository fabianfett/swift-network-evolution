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

#if IMPORT_CRYPTO && !NETWORK_NO_SWIFT_QUIC

/// A client of `QUICConnectionCore` following Retry and Version Negotiation packets.
@available(Network 0.1.0, *)
final class QUICConnectionCoreRetryTests: XCTestCase {
    /// The version, connection IDs and token of the client Initial at the start of `datagram`.
    struct InitialHeader: Equatable {
        var version: UInt32
        var destination: QUICConnectionID
        var source: QUICConnectionID
        var token: [UInt8]

        init(_ datagram: [UInt8]) {
            self.version = datagram[1..<5].reduce(0) { $0 << 8 | UInt32($1) }
            let ids = LockstepPair.connectionIDs(ofInitial: datagram)
            self.destination = ids.destination
            self.source = ids.source
            var reader = CoreReader(datagram.span.bytes, offset: 7 + ids.destination.length + ids.source.length)
            let length = Int(reader.vle()!)
            self.token = reader.array(length)!
        }
    }

    private static func retry(
        for initial: InitialHeader,
        sourceConnectionID: QUICConnectionID,
        token: [UInt8]
    ) throws -> [UInt8] {
        try QUICRetryPacket(
            version: .v1,
            destinationConnectionID: initial.source,
            sourceConnectionID: sourceConnectionID,
            originalDCID: initial.destination,
            token: token
        ).header
    }

    private static func deliver(_ datagram: [UInt8], to machine: inout QUICConnectionCore, now: NetworkClock.Instant) {
        var datagram = datagram
        var span = datagram.mutableSpan
        machine.receive(&span, now: now)
    }

    /// Completes the handshake with a server that sent the Retry.
    private static func connect(
        _ pair: inout LockstepPair,
        first: InitialHeader,
        retrySourceConnectionID: QUICConnectionID,
        serverConfiguration: QUICConnectionCore.Configuration? = nil
    ) {
        pair.server = QUICConnectionCore(
            serverWith: serverConfiguration ?? pair.serverConfiguration,
            localConnectionID: retrySourceConnectionID,
            originalDestinationConnectionID: first.destination,
            peerConnectionID: first.source,
            retrySourceConnectionID: retrySourceConnectionID,
            now: pair.now
        )
        pair.exchange()
    }

    func testAClientFollowsARetry() throws {
        var pair = LockstepPair()
        let first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        XCTAssertEqual(first.token, [])
        let retrySourceConnectionID = QUICConnectionID(8)
        let token: [UInt8] = Array(repeating: 0x7e, count: 40)
        Self.deliver(
            try Self.retry(for: first, sourceConnectionID: retrySourceConnectionID, token: token),
            to: &pair.client,
            now: pair.now
        )
        XCTAssertEqual(pair.client.retrySourceConnectionID, retrySourceConnectionID)
        // The ClientHello goes out again, to the Retry's connection ID, with the token.
        pair.toServer = LockstepPair.drain(&pair.client, now: pair.now)
        let second = InitialHeader(try XCTUnwrap(pair.toServer.first))
        XCTAssertEqual(second.version, QUICVersion.v1.rawValue)
        XCTAssertEqual(second.destination, retrySourceConnectionID)
        XCTAssertEqual(second.source, first.source)
        XCTAssertEqual(second.token, token)
        XCTAssertGreaterThanOrEqual(pair.toServer[0].count, 1200)

        Self.connect(&pair, first: first, retrySourceConnectionID: retrySourceConnectionID)
        XCTAssertTrue(pair.clientEvents.contains(.connected), "client events: \(pair.clientEvents)")
        XCTAssertTrue(pair.serverEvents.contains(.connected), "server events: \(pair.serverEvents)")
        XCTAssertNil(pair.client.closeReason)
    }

    func testARetryWithAnInvalidIntegrityTagIsIgnored() throws {
        var pair = LockstepPair()
        let first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        var retry = try Self.retry(for: first, sourceConnectionID: QUICConnectionID(8), token: [1, 2, 3])
        retry[retry.count - 1] ^= 0xff
        Self.deliver(retry, to: &pair.client, now: pair.now)
        XCTAssertNil(pair.client.retrySourceConnectionID)
        XCTAssertEqual(pair.client.initialToken, [])
        // Nothing is resent before the probe timeout.
        XCTAssertTrue(LockstepPair.drain(&pair.client, now: pair.now).isEmpty)
    }

    func testARetryForAnotherConnectionIsIgnored() throws {
        var pair = LockstepPair()
        var first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        first.source = QUICConnectionID(8)
        Self.deliver(
            try Self.retry(for: first, sourceConnectionID: QUICConnectionID(8), token: [1]),
            to: &pair.client,
            now: pair.now
        )
        XCTAssertNil(pair.client.retrySourceConnectionID)
    }

    func testOnlyTheFirstRetryCounts() throws {
        var pair = LockstepPair()
        let first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        let retrySourceConnectionID = QUICConnectionID(8)
        Self.deliver(
            try Self.retry(for: first, sourceConnectionID: retrySourceConnectionID, token: [1]),
            to: &pair.client,
            now: pair.now
        )
        let second = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        // A second Retry answering the second Initial is ignored.
        Self.deliver(
            try Self.retry(for: second, sourceConnectionID: QUICConnectionID(8), token: [2]),
            to: &pair.client,
            now: pair.now
        )
        XCTAssertEqual(pair.client.retrySourceConnectionID, retrySourceConnectionID)
        XCTAssertEqual(pair.client.initialToken, [1])
    }

    func testARetryAfterTheServersInitialIsIgnored() throws {
        var pair = LockstepPair()
        let initial = LockstepPair.drain(&pair.client, now: pair.now)
        let first = InitialHeader(try XCTUnwrap(initial.first))
        // A real server answers.
        var server = QUICConnectionCore(
            serverWith: pair.serverConfiguration,
            localConnectionID: QUICConnectionID(8),
            originalDestinationConnectionID: first.destination,
            peerConnectionID: first.source,
            now: pair.now
        )
        for datagram in initial {
            Self.deliver(datagram, to: &server, now: pair.now)
        }
        for datagram in LockstepPair.drain(&server, now: pair.now) {
            Self.deliver(datagram, to: &pair.client, now: pair.now)
        }
        XCTAssertTrue(pair.client.receivedFirstServerPacket)
        Self.deliver(
            try Self.retry(for: first, sourceConnectionID: QUICConnectionID(8), token: [1]),
            to: &pair.client,
            now: pair.now
        )
        XCTAssertNil(pair.client.retrySourceConnectionID)
    }

    /// RFC 9000 Section 7.3: a server that sent a Retry repeats its connection ID in
    /// retry_source_connection_id.
    #if DEBUG
    func testTheServerMustRepeatTheRetrySourceConnectionID() throws {
        var pair = LockstepPair()
        let first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        let retrySourceConnectionID = QUICConnectionID(8)
        Self.deliver(
            try Self.retry(for: first, sourceConnectionID: retrySourceConnectionID, token: [9]),
            to: &pair.client,
            now: pair.now
        )
        var serverConfiguration = pair.serverConfiguration
        serverConfiguration.transportParametersForTesting = { $0.remove(.retrySCID) }
        Self.connect(
            &pair,
            first: first,
            retrySourceConnectionID: retrySourceConnectionID,
            serverConfiguration: serverConfiguration
        )
        XCTAssertEqual(
            pair.client.closeReason,
            .transportError(
                errorCode: CoreTransportError.protocolViolation,
                reason: "retry_source_connection_id mismatch"
            )
        )
        XCTAssertFalse(pair.clientEvents.contains(.connected))
    }
    #endif

    // MARK: Version Negotiation

    private static func versionNegotiation(for initial: InitialHeader, versions: [QUICVersion]) throws -> [UInt8] {
        try QUICVersionNegotiation(
            destinationConnectionID: initial.source,
            sourceConnectionID: initial.destination,
            supportedVersions: versions
        ).header
    }

    private static func clientConfiguration(version: UInt32) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.clientInitialVersion = version
        return configuration
    }

    func testAClientSwitchesToVersion1AfterVersionNegotiation() throws {
        var pair = LockstepPair(
            clientConfiguration: Self.clientConfiguration(version: QUICVersion.negotiationPattern.rawValue)
        )
        let first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        XCTAssertEqual(first.version, QUICVersion.negotiationPattern.rawValue)
        Self.deliver(try Self.versionNegotiation(for: first, versions: [.v1]), to: &pair.client, now: pair.now)
        pair.toServer = LockstepPair.drain(&pair.client, now: pair.now)
        let second = InitialHeader(try XCTUnwrap(pair.toServer.first))
        XCTAssertEqual(second.version, QUICVersion.v1.rawValue)
        XCTAssertEqual(second.destination, first.destination)
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected), "client events: \(pair.clientEvents)")
        XCTAssertTrue(pair.serverEvents.contains(.connected), "server events: \(pair.serverEvents)")
    }

    /// RFC 9000 Section 6.2: one that lists the version the client sent is forged or stale.
    func testAVersionNegotiationListingOurVersionIsIgnored() throws {
        var pair = LockstepPair()
        let first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        XCTAssertEqual(first.version, QUICVersion.v1.rawValue)
        Self.deliver(try Self.versionNegotiation(for: first, versions: [.v1]), to: &pair.client, now: pair.now)
        XCTAssertTrue(LockstepPair.drain(&pair.client, now: pair.now).isEmpty, "nothing is resent")
        XCTAssertNil(pair.client.closeReason)
        XCTAssertFalse(pair.client.receivedVersionNegotiation)
    }

    func testAClientGivesUpWithoutACommonVersion() throws {
        var pair = LockstepPair(clientConfiguration: Self.clientConfiguration(version: 0x0a0a_0a0a))
        let first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        Self.deliver(
            try Self.versionNegotiation(for: first, versions: [.negotiationPattern]),
            to: &pair.client,
            now: pair.now
        )
        XCTAssertEqual(
            pair.client.closeReason,
            .transportError(errorCode: CoreTransportError.internalError, reason: "No supported version")
        )
        XCTAssertTrue(LockstepPair.drain(&pair.client, now: pair.now).isEmpty)
    }

    func testVersionNegotiationForAnotherConnectionIsIgnored() throws {
        var pair = LockstepPair(
            clientConfiguration: Self.clientConfiguration(version: QUICVersion.negotiationPattern.rawValue)
        )
        var first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        first.destination = QUICConnectionID(8)
        Self.deliver(try Self.versionNegotiation(for: first, versions: [.v1]), to: &pair.client, now: pair.now)
        XCTAssertTrue(LockstepPair.drain(&pair.client, now: pair.now).isEmpty)
        XCTAssertEqual(pair.client.version, QUICVersion.negotiationPattern.rawValue)
    }

    func testOnlyTheFirstVersionNegotiationCounts() throws {
        var pair = LockstepPair(
            clientConfiguration: Self.clientConfiguration(version: QUICVersion.negotiationPattern.rawValue)
        )
        let first = InitialHeader(try XCTUnwrap(LockstepPair.drain(&pair.client, now: pair.now).first))
        Self.deliver(try Self.versionNegotiation(for: first, versions: [.v1]), to: &pair.client, now: pair.now)
        _ = LockstepPair.drain(&pair.client, now: pair.now)
        // A second one, even without a common version, changes nothing.
        Self.deliver(try Self.versionNegotiation(for: first, versions: []), to: &pair.client, now: pair.now)
        XCTAssertNil(pair.client.closeReason)
        XCTAssertEqual(pair.client.version, QUICVersion.v1.rawValue)
    }
}

#endif
