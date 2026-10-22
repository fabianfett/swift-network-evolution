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

// This class won't be shared across thread boundaries.
@available(Network 0.1.0, *)
package final class LogPrefixer: @unchecked Sendable {
    package var log: NetworkLoggerState
    package var logIDString: String {
        get {
            log.logPrefix
        }
        set {
            log.logPrefix = log.logPrefix + newValue
        }
    }
    package init(_ logPrefix: String = "") {
        self.log = NetworkLoggerState(logPrefix)
    }

    #if DisableDebugLogging
    @inline(always)
    public func info(_ message: @autoclosure () -> String) {}

    @inline(always)
    public func debug(_ message: @autoclosure () -> String) {}

    @inline(always)
    public func datapath(_ message: @autoclosure () -> String) {}
    #else
    #if !NETWORK_EMBEDDED
    public func info(
        _ message: @autoclosure () -> String,
        callingFunction: StaticString = #function
    ) {
        log.info(message(), callingFunction: callingFunction)
    }
    public func debug(
        _ message: @autoclosure () -> String,
        callingFunction: StaticString = #function
    ) {
        log.debug(message(), callingFunction: callingFunction)
    }
    public func datapath(
        _ message: @autoclosure () -> String,
        callingFunction: StaticString = #function
    ) {
        log.datapath(message(), callingFunction: callingFunction)
    }
    #else
    public func info(_ message: String, callingFunction: StaticString = #function) {
        log.info(message, callingFunction: callingFunction)
    }
    public func debug(_ message: String, callingFunction: StaticString = #function) {
        log.debug(message, callingFunction: callingFunction)
    }
    public func datapath(_ message: String, callingFunction: StaticString = #function) {
        log.datapath(message, callingFunction: callingFunction)
    }
    #endif
    #endif

    #if DisableErrorLogging
    @inline(always)
    public func fault(_ message: @autoclosure () -> String) {}

    @inline(always)
    public func error(_ message: @autoclosure () -> String) {}

    @inline(always)
    public func notice(_ message: @autoclosure () -> String) {}
    #else
    #if !NETWORK_EMBEDDED
    public func fault(
        _ message: @autoclosure () -> String,
        callingFunction: StaticString = #function
    ) {
        log.fault(message(), callingFunction: callingFunction)
    }
    public func error(
        _ message: @autoclosure () -> String,
        callingFunction: StaticString = #function
    ) {
        log.error(message(), callingFunction: callingFunction)
    }
    public func notice(
        _ message: @autoclosure () -> String,
        callingFunction: StaticString = #function
    ) {
        log.notice(message(), callingFunction: callingFunction)
    }
    #else
    public func fault(_ message: String, callingFunction: StaticString = #function) {
        log.fault(message, callingFunction: callingFunction)
    }
    public func error(_ message: String, callingFunction: StaticString = #function) {
        log.error(message, callingFunction: callingFunction)
    }
    public func notice(_ message: String, callingFunction: StaticString = #function) {
        log.notice(message, callingFunction: callingFunction)
    }
    #endif
    #endif
}

#if !NETWORK_NO_SWIFT_QUIC
@available(Network 0.1.0, *)
package protocol PrefixedLoggable: ~Copyable {
    var log: LogPrefixer { get }
}
#endif

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public struct NetworkLoggerState: ~Copyable {
    public var logPrefix: String

    public init(_ prefix: String = "") {
        logPrefix = prefix
    }

    #if DisableDebugLogging
    @inline(always)
    public func info(_ message: @autoclosure () -> String) {}

    @inline(always)
    public func debug(_ message: @autoclosure () -> String) {}

    @inline(always)
    public func datapath(_ message: @autoclosure () -> String) {}
    #else
    #if !NETWORK_EMBEDDED
    public func info(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {
        if !Logger.swiftNetworkProtocolLoggingEnabled {
            return
        }
        let logPrefix = logPrefix
        let message = message()
        Logger.proto.info("\(callingFunction) \(logPrefix) \(message)")
    }
    public func debug(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {
        if !Logger.swiftNetworkProtocolLoggingEnabled {
            return
        }
        let logPrefix = logPrefix
        let message = message()
        Logger.proto.debug("\(callingFunction) \(logPrefix) \(message)")
    }
    #if !NETWORK_PRIVATE
    #if DatapathLogging
    public func datapath(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {
        if !Logger.swiftNetworkDatapathLoggingEnabled {
            return
        }
        let logPrefix = logPrefix
        let message = message()
        Logger.proto.debug("\(callingFunction) \(logPrefix) \(message)")
    }
    #else
    @inline(always)
    public func datapath(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {}
    #endif
    #endif
    #else
    public func info(_ message: String, callingFunction: StaticString = #function) {
        if !Logger.swiftNetworkProtocolLoggingEnabled {
            return
        }
        let logPrefix = logPrefix
        Logger.proto.info("\(callingFunction) \(logPrefix) \(message)")
    }

    public func debug(_ message: String, callingFunction: StaticString = #function) {
        if !Logger.swiftNetworkProtocolLoggingEnabled {
            return
        }
        let logPrefix = logPrefix
        Logger.proto.debug("\(callingFunction) \(logPrefix) \(message)")
    }

    #if DatapathLogging
    public func datapath(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {
        if !Logger.swiftNetworkDatapathLoggingEnabled {
            return
        }
        let logPrefix = logPrefix
        let message = message()
        Logger.proto.debug("\(callingFunction) \(logPrefix) \(message)")
    }
    #else
    @inline(always)
    public func datapath(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {}
    #endif

    #endif
    #endif

    #if DisableErrorLogging
    @inline(always)
    public func notice(_ message: @autoclosure () -> String) {}

    @inline(always)
    public func error(_ message: @autoclosure () -> String) {}

    @inline(always)
    public func fault(_ message: @autoclosure () -> String) {}
    #else
    #if !NETWORK_EMBEDDED
    public func fault(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {
        let logPrefix = logPrefix
        let message = message()
        Logger.proto.fault("\(callingFunction) \(logPrefix) \(message)")
    }
    public func error(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {
        let logPrefix = logPrefix
        let message = message()
        Logger.proto.error("\(callingFunction) \(logPrefix) \(message)")
    }
    public func notice(_ message: @autoclosure () -> String, callingFunction: StaticString = #function) {
        let logPrefix = logPrefix
        let message = message()
        #if os(Linux) || os(Android)
        Logger.proto.notice("\(callingFunction) \(logPrefix) \(message)")
        #else
        Logger.proto.log("\(callingFunction) \(logPrefix) \(message)")
        #endif
    }
    #else
    public func fault(_ message: String, callingFunction: StaticString = #function) {
        let logPrefix = logPrefix
        Logger.proto.fault("\(callingFunction) \(logPrefix) \(message)")
    }

    public func error(_ message: String, callingFunction: StaticString = #function) {
        let logPrefix = logPrefix
        Logger.proto.error("\(callingFunction) \(logPrefix) \(message)")
    }

    public func notice(_ message: String, callingFunction: StaticString = #function) {
        let logPrefix = logPrefix
        #if os(Linux)
        Logger.proto.notice("\(callingFunction) \(logPrefix) \(message)")
        #else
        Logger.proto.log("\(callingFunction) \(logPrefix) \(message)")
        #endif
    }
    #endif
    #endif
}
