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

#if !targetEnvironment(simulator) && (os(iOS) || os(macOS) || os(Linux) || os(Android))

#if canImport(SwiftNetwork)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import SwiftNetwork
#elseif canImport(Network)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import Network
#endif

#if canImport(SwiftNetworkTestHarness)
@_spi(TestHarness) @_spi(Essentials) @_spi(ProtocolProvider) import SwiftNetworkTestHarness
#endif

#if IMPORT_SWIFTTLS
#if EXPORT_SWIFTTLS
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS
#else
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) @_weakLinked internal import SwiftTLS
#endif
#endif

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

#if canImport(Glibc)
import Glibc
internal import Logging
#elseif canImport(Android)
import Android
internal import Logging
#elseif canImport(Musl)
import Musl
internal import Logging
#elseif canImport(os)
internal import os
#endif

#if IMPORT_SWIFTTLS
#if canImport(SwiftTLS)
@available(Network 0.1.0, *)
final class SwiftNetworkQUICIdleTests: NetTestCase {
    func testQUICConnectionIdleTracksOwedAck() {
        // The idle state reported to the lower protocol must account for outstanding
        // transmit obligations, not just the application's idle mark.
        // A connection that still owes the peer an ACK is not idle.
        QUICTestHarness().runQUICTest(
            dataBlock: Array("Hello World!".utf8),
            afterHandshake: { harness in
                // The test relies on the client still owing a delayed ACK for the echoed
                // data when the idle state is evaluated, and sends that ACK explicitly.
                // Stretch the delayed ACK timer so it cannot fire on its own before then;
                // with the default 25ms delay, slow CI machines can lose that race.
                let expectation = XCTestExpectation(description: "Wait for delayed ACK timer to be extended")
                harness.context.async {
                    if let client = harness.state?.clientInstance {
                        client.fromExternal { eventContext in
                            if let box = client.coreBox {
                                box.core.configuration.maxAckDelay = .seconds(30)
                                // The handshake may have already armed the timer with the default
                                // delay, which a later packet keeps, so re-arm it with the
                                // extended delay.
                                if box.core.acks[.applicationData].ackDeadline != nil {
                                    box.core.acks[.applicationData].ackDeadline = client.now.advanced(by: .seconds(30))
                                }
                            }
                            client.coreAfterUpdate(in: &eventContext)
                        }
                    }
                    // Keep the server's view of the client's ACK delay consistent, otherwise
                    // its PTO fires while the ACK is held and the probe forces an immediate ACK.
                    harness.state?.serverInstance.coreBox?.core.recovery.maxAckDelay = .seconds(30)
                    expectation.fulfill()
                }
                let waitResult = XCTWaiter.wait(for: [expectation], timeout: 2.0)
                XCTAssertEqual(waitResult, .completed, "Delayed ACK timer should be extended")
            },
            afterData: { harness in
                // Verify the reported idle state follows the transmit obligations
                let expectation = XCTestExpectation(description: "Wait for idle state to be evaluated")
                harness.context.async {
                    let client = harness.state?.clientInstance
                    XCTAssertNotNil(client, "Client instance needs to be present to proceed")
                    if let client, let box = client.coreBox {
                        XCTAssertFalse(
                            client.currentPath?.reportedIdleEvent ?? true,
                            "Client should not have reported idle before the application marks idle"
                        )

                        for upperHarness in harness.state?.clientHarness.upperHarnesses ?? [] {
                            upperHarness.invokeConnectionIdleEvent()
                        }

                        // The echoed data has been received but not acknowledged yet, so
                        // a delayed ACK is still owed and the connection is not idle.
                        XCTAssertNotNil(
                            box.core.acks[.applicationData].ackDeadline,
                            "Client should still owe the peer a delayed ACK"
                        )
                        XCTAssertFalse(box.core.isQuiescent, "Client owes an ACK")
                        XCTAssertFalse(
                            client.currentPath?.reportedIdleEvent ?? true,
                            "Client should not have reported idle while an ACK is owed to the peer"
                        )

                        // Once the delayed ACK has been sent there are no obligations left: the
                        // delayed ACK timer fires now.
                        client.fromExternal { eventContext in
                            box.core.acks[.applicationData].ackDeadline = client.now
                            box.core.handleTimeout(now: client.now)
                            client.coreAfterUpdate(in: &eventContext)
                        }
                        XCTAssertNil(
                            box.core.acks[.applicationData].ackDeadline,
                            "Client should not owe the peer an ACK once the delayed ACK has been sent"
                        )
                        XCTAssertFalse(box.core.acks[.applicationData].ackNeeded, "The ACK went out")
                        XCTAssertTrue(
                            client.currentPath?.reportedIdleEvent ?? false,
                            "Client should have reported idle once the owed ACK has been sent"
                        )

                        for upperHarness in harness.state?.clientHarness.upperHarnesses ?? [] {
                            upperHarness.invokeConnectionReusedEvent()
                        }
                        XCTAssertFalse(
                            client.currentPath?.reportedIdleEvent ?? true,
                            "Client should not have reported idle after the application reuses the connection"
                        )
                    } else {
                        XCTFail("The client has no core")
                    }
                    expectation.fulfill()
                }
                let waitResult = XCTWaiter.wait(for: [expectation], timeout: 2.0)
                XCTAssertEqual(waitResult, .completed, "Idle state evaluation should complete")
            }
        )
    }

    // testDelayedAckTimerCanSendPMTUDProbe guarded the classes' timer against reading the ACK
    // state it held while a PMTUD probe went out. The core owns its state, so that can't happen;
    // QUICConnectionCorePMTUDTests.testTheDelayedAckTimerSendsAProbeAndTheAck pins what is left:
    // the probe and the ACK both go out.
}
#endif
#endif
#endif
