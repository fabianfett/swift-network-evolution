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
#if canImport(SwiftTLS) && SWIFTTLS_CERTIFICATE_VERIFICATION && canImport(Synchronization)

#if EXPORT_SWIFTTLS
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS
#else
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) @_weakLinked internal import SwiftTLS
#endif

import Synchronization

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

/// Asynchronous certificate verification in `QUICConnectionCore`: the handshake stops until the
/// driver resumes it with the result.
@available(Network 0.1.0, *)
final class QUICConnectionCoreAsyncVerificationTests: XCTestCase {
    /// What the verifier and the continuation hand over, from whatever thread they run on.
    private final class Handover: Sendable {
        let deliverResult = Mutex<(@Sendable (VerificationResult) -> Void)?>(nil)
        let result = Mutex<PendingAsyncResult?>(nil)
        let verifications = Mutex(0)
    }

    private static func pair(verifier handover: Handover) -> LockstepPair {
        let serverKey = P256.Signing.PrivateKey()
        var clientTLS = SwiftTLSProtocol.Options()
        clientTLS.applicationProtocols = ["qsm-test"]
        clientTLS.serverName = "quic-test.local"
        // Trusted raw public keys would take precedence over the verifier.
        clientTLS.tlsOptions.asyncVerifier = AsyncVerifier(availableCertificateTypes: [.rawPublicKey]) { info in
            handover.verifications.withLock { $0 += 1 }
            guard let deliverResult = info.deliverResult else {
                return .invalid(reason: "No way to deliver an async result")
            }
            handover.deliverResult.withLock { $0 = deliverResult }
            return .waiting
        }
        var serverTLS = SwiftTLSProtocol.Options()
        serverTLS.applicationProtocols = ["qsm-test"]
        serverTLS.rawPrivateKey = [UInt8](serverKey.rawRepresentation)
        let pair = LockstepPair(clientTLSOptions: clientTLS, serverTLSOptions: serverTLS)
        pair.client.setAsyncContinuationHandler { result in
            handover.result.withLock { $0 = result }
        }
        return pair
    }

    private static func verify(_ verification: VerificationResult, _ handover: Handover) -> PendingAsyncResult? {
        let deliverResult = handover.deliverResult.withLock { $0.take() }
        deliverResult?(verification)
        return handover.result.withLock { $0.take() }
    }

    func testTheHandshakeWaitsForTheVerifierAndCompletesWhenItAccepts() throws {
        let handover = Handover()
        var pair = Self.pair(verifier: handover)
        pair.exchange()
        XCTAssertEqual(handover.verifications.withLock { $0 }, 1)
        XCTAssertFalse(pair.client.isHandshakeComplete, "the client waits for the verifier")
        XCTAssertFalse(pair.clientEvents.contains(.connected))
        XCTAssertNil(handover.result.withLock { $0 }, "nothing arrives before the verifier answers")

        let result = try XCTUnwrap(Self.verify(.valid, handover), "the continuation gets the result")
        pair.client.resumeHandshake(with: result, now: pair.now)
        pair.exchange()
        pair.clientEvents += LockstepPair.events(&pair.client)
        XCTAssertTrue(pair.clientEvents.contains(.connected), "client events: \(pair.clientEvents)")
        XCTAssertTrue(pair.serverEvents.contains(.connected), "server events: \(pair.serverEvents)")
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        XCTAssertNil(pair.client.closeReason)
    }

    func testTheHandshakeFailsWhenTheVerifierRejects() throws {
        let handover = Handover()
        var pair = Self.pair(verifier: handover)
        pair.exchange()
        XCTAssertFalse(pair.client.isHandshakeComplete)

        let result = try XCTUnwrap(Self.verify(.invalid(reason: "untrusted"), handover))
        pair.client.resumeHandshake(with: result, now: pair.now)
        pair.exchange()
        pair.clientEvents += LockstepPair.events(&pair.client)
        XCTAssertFalse(pair.clientEvents.contains(.connected))
        guard case .transportError(let errorCode, _) = pair.client.closeReason else {
            XCTFail("closed with \(String(describing: pair.client.closeReason))")
            return
        }
        // A failed handshake closes with a CRYPTO_ERROR (RFC 9001 Section 4.8).
        XCTAssertEqual(errorCode & ~0xff, 0x0100)
    }

    func testAResultAfterTheConnectionClosedIsIgnored() throws {
        let handover = Handover()
        var pair = Self.pair(verifier: handover)
        pair.exchange()
        // The result was on its way to the driver when the connection closed.
        let result = try XCTUnwrap(Self.verify(.valid, handover))
        pair.client.close(errorCode: 0, isApplication: true, now: pair.now)
        pair.client.resumeHandshake(with: result, now: pair.now)
        XCTAssertFalse(pair.client.isHandshakeComplete)
        XCTAssertEqual(pair.client.closeReason, .local(errorCode: 0, isApplication: true))
    }

    /// Records that the continuation handler, and what it captured, went away.
    private final class Witness: Sendable {
        let flag: Flag

        init(_ flag: Flag) {
            self.flag = flag
        }

        deinit {
            self.flag.released.withLock { $0 = true }
        }
    }

    private final class Flag: Sendable {
        let released = Mutex(false)
    }

    /// Installs a continuation handler that captures an object, and returns what learns when the
    /// object is released.
    private static func installCapturingHandler(on pair: inout LockstepPair, _ handover: Handover) -> Flag {
        let flag = Flag()
        let witness = Witness(flag)
        pair.client.setAsyncContinuationHandler { result in
            _ = witness
            handover.result.withLock { $0 = result }
        }
        return flag
    }

    func testClosingDuringVerificationReleasesTheContinuationHandlerRightAway() {
        // A local close, the peer's CONNECTION_CLOSE, and a transport error.
        for closing in 0..<3 {
            let handover = Handover()
            var pair = Self.pair(verifier: handover)
            let flag = Self.installCapturingHandler(on: &pair, handover)
            pair.exchange()
            XCTAssertEqual(handover.verifications.withLock { $0 }, 1)
            // The verifier never answers, and keeps nothing that leads to the handler: only the
            // handshake does.
            handover.deliverResult.withLock { $0 = nil }
            XCTAssertFalse(flag.released.withLock { $0 }, "the handshake still waits for the verifier")
            switch closing {
            case 0:
                pair.client.close(errorCode: 0, isApplication: true, now: pair.now)
            case 1:
                if var server = pair.server.take() {
                    server.close(errorCode: 3, isApplication: true, now: pair.now)
                    pair.server = consume server
                }
                pair.exchange()
            default:
                pair.client.closeWithError(CoreTransportError.protocolViolation, reason: "test", now: pair.now)
            }
            XCTAssertTrue(pair.client.isTerminating, "case \(closing)")
            XCTAssertNotNil(pair.client.nextDeadline, "case \(closing): the connection waits out its timer")
            // Long before the connection is closed, the handler and what it holds are gone.
            XCTAssertTrue(flag.released.withLock { $0 }, "case \(closing)")
        }
    }
}

#endif
#endif
