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
#if !NETWORK_STANDALONE && canImport(Foundation)
// Needed for writing the qlog file
import struct Foundation.Data
import class Foundation.FileManager
import class Foundation.JSONSerialization
#endif  // !NETWORK_EMBEDDED

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

@_spi(Essentials)
@available(Network 0.1.0, *)
public struct QLogConfiguration: CustomStringConvertible, Sendable {
    public var logTitle: String?
    public var logDescription: String?
    public var logPath: String
    public var description: String {

        "title: \(logTitle ?? ""), description: \(logDescription ?? ""), path: \(logPath)"
    }
    public init(logTitle: String? = nil, logDescription: String? = nil, logPath: String) {
        self.logTitle = logTitle
        self.logDescription = logDescription
        self.logPath = logPath
    }
}

enum QLogFlowType: String {
    case client
    case server
}

enum QLogOwner: String {
    case local
    case remote
}

#if QlogOutput

enum QLogPacketSentReceivedTrigger: String {
    /// `QUICConnectionCore` doesn't report why it sent a packet.
    case unknown = "unknown"
}

@available(Network 0.1.0, *)
struct EventParametersSet {
    let owner: QLogOwner?
    let resumptionAllowed: Bool?
    let earlyDataEnabled: Bool?
    let tlsCipher: String
    let originalDCID: QUICConnectionID?
    let initialSCID: QUICConnectionID?
    let retrySCID: QUICConnectionID?
    let disableActiveMigration: Bool?
    let maxIdleTimeout: Int?
    let maxUDPPayloadSize: Int?
    let ackDelayExponent: Int?
    let maxAckDelay: NetworkDuration?
    let activeConnectionIDLimit: Int?
    let initialMaxData: Int?
    let initialMaxStreamDataBidirectionalRemote: Int?
    let initialMaxStreamDataBidirectionalLocal: Int?
    let initialMaxStreamDataUnidirectional: Int?
    let initialMaxStreamsBidirectional: Int?
    let initialMaxStreamsUnidirectional: Int?
    let preferredAddress: PreferredAddress?

    func dumpData() -> [String: Any] {
        var data: [String: Any] = [:]
        data["owner"] = owner?.rawValue
        data["resumption_allowed"] = resumptionAllowed?.description
        data["early_data_enabled"] = earlyDataEnabled?.description
        data["tls_cipher"] = tlsCipher
        data["original_destination_connection_id"] = originalDCID?.description
        data["retry_source_connection_id"] = retrySCID?.description
        data["initial_source_connection_id"] = initialSCID?.description
        data["disable_active_migration"] = disableActiveMigration?.description
        data["max_idle_timeout"] = maxIdleTimeout
        data["max_udp_payload_size"] = maxUDPPayloadSize
        data["ack_delay_exponent"] = ackDelayExponent
        // qlog reports max_ack_delay in milliseconds, matching the wire encoding.
        data["max_ack_delay"] = maxAckDelay.map { Int($0.milliseconds) }
        data["active_connection_id_limit"] = activeConnectionIDLimit
        data["initial_max_data"] = initialMaxData
        data["initial_max_stream_data_bidi_local"] = initialMaxStreamDataBidirectionalLocal
        data["initial_max_stream_data_bidi_remote"] = initialMaxStreamDataBidirectionalRemote
        data["initial_max_stream_data_uni"] = initialMaxStreamDataUnidirectional
        data["initial_max_streams_bidi"] = initialMaxStreamsBidirectional
        data["initial_max_streams_uni"] = initialMaxStreamsUnidirectional
        data["preferred_address"] = preferredAddress
        if let preferredAddress {
            data["ip_v4"] = preferredAddress.ipv4Address.description
            data["ip_v6"] = preferredAddress.ipv6Address.description
            data["port_v4"] = preferredAddress.ipv4Port.description
            data["port_v6"] = preferredAddress.ipv6Port.description
            data["connection_id"] = preferredAddress.connectionID.description
            data["stateless_reset_token"] = preferredAddress.statelessResetToken.description
        }
        return data
    }
}

@available(Network 0.1.0, *)
struct EventPacket {
    let packetType: PacketType
    let packetHeader: PacketHeader
    let frameList: EventFrames
    /// `nil` for a lost packet.
    let trigger: QLogPacketSentReceivedTrigger?
}

@available(Network 0.1.0, *)
struct PacketHeader {
    let packetNumber: PacketNumber
    let packetSize: UInt64
    let payloadLength: UInt64
    var version: QUICVersion = .v1
    var scil: Int = 0
    var dcil: Int = 0
    var scid: String = ""
    var dcid: String = ""

    /// The header of a packet `QUICConnectionCore` reported, which only knows its number and size.
    init(packetNumber: UInt64, size: Int) {
        self.packetNumber = PacketNumber(Int64(truncatingIfNeeded: packetNumber))
        self.packetSize = UInt64(max(0, size))
        self.payloadLength = .max
    }

    func dumpData() -> [String: Any] {
        var data: [String: Any] = [:]
        data["packet_number"] = String(packetNumber.value)
        data["packet_size"] = QLog.wrapUInt64IfNotMax(packetSize)
        data["length"] = QLog.wrapUInt64IfNotMax(payloadLength)
        data["version"] = version.rawValue
        if scil != 0 {
            data["scil"] = scil
            data["scid"] = scid
        }
        if dcil != 0 {
            data["dcil"] = dcil
            data["dcid"] = dcid
        }
        return data
    }
}

@available(Network 0.1.0, *)
enum Event {
    case parametersSet(EventParametersSet, timestamp: NetworkDuration)
    case packetSent(EventPacket, timestamp: NetworkDuration)
    case packetReceived(EventPacket, timestamp: NetworkDuration)
    case packetLost(EventPacket, timestamp: NetworkDuration)

    func commonEventData(timestamp: NetworkDuration) -> [Any] {
        // All timestamps and time-related values (e.g., offsets) in qlog are logged as
        // float64 in the millisecond resolution
        [timestamp.milliseconds, self.category(), self.description()]
    }

    func eventData() -> [Any] {
        switch self {
        case .packetReceived(let eventPacket, let timestamp),
            .packetSent(let eventPacket, let timestamp),
            .packetLost(let eventPacket, let timestamp):

            var content: [Any] = self.commonEventData(timestamp: timestamp)
            var dataContent: [String: Any] = [:]
            dataContent["packet_type"] = eventPacket.packetType.rawValue

            dataContent["header"] = eventPacket.packetHeader.dumpData()

            dataContent["frames"] = eventPacket.frameList.dumpData()
            dataContent["trigger"] = eventPacket.trigger?.rawValue
            content.append(dataContent)
            return content

        case .parametersSet(let event, let timestamp):
            var content: [Any] = self.commonEventData(timestamp: timestamp)
            let dataContent: [String: Any] = event.dumpData()
            content.append(dataContent)
            return content
        }
    }

    func category() -> String {
        switch self {
        case .parametersSet, .packetSent, .packetReceived:
            return "TRANSPORT"
        case .packetLost:
            return "RECOVERY"
        }
    }

    func description() -> String {
        switch self {
        case .parametersSet:
            return "PARAMETERS_SET"
        case .packetSent:
            return "PACKET_SENT"
        case .packetReceived:
            return "PACKET_RECEIVED"
        case .packetLost:
            return "PACKET_LOST"
        }
    }
}

@available(Network 0.1.0, *)
struct EventFrames {
    /// The frames of a packet `QUICConnectionCore` reported, which only names their types.
    var frameTypes: [QUICConnectionCore.PacketEvent.FrameType] = []

    init() {}
    init(frameTypes: [QUICConnectionCore.PacketEvent.FrameType]) {
        self.frameTypes = frameTypes
    }
    func dumpData() -> [Any] {
        var data: [Any] = []
        for frameType in frameTypes {
            data.append(["frame_type": frameType.qlogName])
        }
        return data
    }
}

@available(Network 0.1.0, *)
extension QUICConnectionCore.PacketEvent.FrameType {
    /// The `frame_type` qlog writes.
    var qlogName: String {
        switch self {
        case .padding: return "padding"
        case .ping: return "ping"
        case .ack: return "ack"
        case .resetStream: return "reset_stream"
        case .stopSending: return "stop_sending"
        case .crypto: return "crypto"
        case .newToken: return "new_token"
        case .stream: return "stream"
        case .maxData: return "max_data"
        case .maxStreamData: return "max_stream_data"
        case .maxStreams: return "max_streams"
        case .dataBlocked: return "data_blocked"
        case .streamDataBlocked: return "stream_data_blocked"
        case .streamsBlocked: return "streams_blocked"
        case .newConnectionID: return "new_connection_id"
        case .retireConnectionID: return "retire_connection_id"
        case .pathChallenge: return "path_challenge"
        case .pathResponse: return "path_response"
        case .connectionClose: return "connection_close"
        case .handshakeDone: return "handshake_done"
        case .datagram: return "datagram"
        case .unknown: return "unknown"
        }
    }
}

enum PacketType: String {
    case unknown = "unknown"
    case initial = "initial"
    case handshake = "handshake"
    case zeroRTT = "0RTT"
    case oneRTT = "1RTT"
    case retry = "retry"
    case versionNegotiation = "version_negotiation"

    @available(Network 0.1.0, *)
    init(_ type: QUICConnectionCore.PacketEvent.PacketType) {
        switch type {
        case .initial: self = .initial
        case .handshake: self = .handshake
        case .zeroRTT: self = .zeroRTT
        case .oneRTT: self = .oneRTT
        }
    }
}

@available(Network 0.1.0, *)
final class QLog {
    private var eventsList: [Event]
    private var topLevelObject: [String: Any]
    private let context: NetworkContext
    private let startTime: NetworkClock.Instant
    var configuration: QLogConfiguration?

    public init(configuration: QLogConfiguration? = nil, context: NetworkContext) {
        self.configuration = configuration
        self.context = context
        self.startTime = context.now
        self.eventsList = []
        self.topLevelObject = [:]
        self.topLevelObject["qlog_version"] = "draft-01"
        if let title = configuration?.logTitle {
            self.topLevelObject["title"] = title
        }
        if let description = configuration?.description {
            self.topLevelObject["description"] = description
        }
    }

    static func wrapUInt64IfNotMax(_ value: UInt64) -> UInt64? {
        if value == UInt64.max {
            return nil
        }
        return value
    }

    private func calculateTimestamp(_ timestamp: NetworkClock.Instant) -> NetworkDuration {
        if timestamp == .zero {
            return .zero
        } else {
            return startTime.duration(to: timestamp)
        }
    }

    /// Logs a packet `QUICConnectionCore` sent, received or declared lost.
    func packetEvent(_ packetEvent: QUICConnectionCore.PacketEvent) {
        let timestamp = self.calculateTimestamp(packetEvent.time)
        let header = PacketHeader(packetNumber: packetEvent.packetNumber, size: packetEvent.size)
        let packetType = PacketType(packetEvent.packetType)
        let frames = EventFrames(frameTypes: packetEvent.frames)
        switch packetEvent.kind {
        case .sent:
            let packet = EventPacket(
                packetType: packetType,
                packetHeader: header,
                frameList: frames,
                trigger: .unknown
            )
            self.eventsList.append(.packetSent(packet, timestamp: timestamp))
        case .received:
            let packet = EventPacket(
                packetType: packetType,
                packetHeader: header,
                frameList: frames,
                trigger: .unknown
            )
            self.eventsList.append(.packetReceived(packet, timestamp: timestamp))
        case .lost:
            let packet = EventPacket(
                packetType: packetType,
                packetHeader: header,
                frameList: frames,
                trigger: nil
            )
            self.eventsList.append(.packetLost(packet, timestamp: timestamp))
        }
    }

    public func parametersSet(
        owner: QLogOwner?,
        resumptionAllowed: Bool?,
        earlyDataEnabled: Bool?,
        tlsCipher: String,
        originalDCID: QUICConnectionID?,
        initialSCID: QUICConnectionID?,
        retrySCID: QUICConnectionID?,
        disableActiveMigration: Bool?,
        maxIdleTimeout: Int?,
        maxUDPPayloadSize: Int?,
        ackDelayExponent: Int?,
        maxAckDelay: NetworkDuration?,
        activeConnectionIDLimit: Int?,
        initialMaxData: Int?,
        initialMaxStreamDataBidirectionalRemote: Int?,
        initialMaxStreamDataBidirectionalLocal: Int?,
        initialMaxStreamDataUnidirectional: Int?,
        initialMaxStreamsBidirectional: Int?,
        initialMaxStreamsUnidirectional: Int?,
        preferredAddress: PreferredAddress?,
        timestamp: NetworkClock.Instant
    ) {
        let parametersEvent = EventParametersSet(
            owner: owner,
            resumptionAllowed: resumptionAllowed,
            earlyDataEnabled: earlyDataEnabled,
            tlsCipher: tlsCipher,
            originalDCID: originalDCID,
            initialSCID: initialSCID,
            retrySCID: retrySCID,
            disableActiveMigration: disableActiveMigration,
            maxIdleTimeout: maxIdleTimeout,
            maxUDPPayloadSize: maxUDPPayloadSize,
            ackDelayExponent: ackDelayExponent,
            maxAckDelay: maxAckDelay,
            activeConnectionIDLimit: activeConnectionIDLimit,
            initialMaxData: initialMaxData,
            initialMaxStreamDataBidirectionalRemote: initialMaxStreamDataBidirectionalRemote,
            initialMaxStreamDataBidirectionalLocal: initialMaxStreamDataBidirectionalLocal,
            initialMaxStreamDataUnidirectional: initialMaxStreamDataUnidirectional,
            initialMaxStreamsBidirectional: initialMaxStreamsBidirectional,
            initialMaxStreamsUnidirectional: initialMaxStreamsUnidirectional,
            preferredAddress: preferredAddress
        )
        let event = Event.parametersSet(parametersEvent, timestamp: calculateTimestamp(timestamp))
        eventsList.append(event)
    }

    public func parametersSet(
        owner: QLogOwner?,
        transportParameters: TransportParameters,
        timestamp: NetworkClock.Instant
    ) {
        parametersSet(
            owner: owner,
            resumptionAllowed: nil,
            earlyDataEnabled: nil,
            tlsCipher: "",
            originalDCID: transportParameters[TransportParameterTypes.originalDCID]?.connectionID,
            initialSCID: transportParameters[TransportParameterTypes.initialSCID]?.connectionID,
            retrySCID: transportParameters[TransportParameterTypes.retrySCID]?.connectionID,
            disableActiveMigration: transportParameters[
                TransportParameterTypes.disableActiveMigration
            ] != nil ? true : false,
            maxIdleTimeout: transportParameters[TransportParameterTypes.maxIdleTimeout]?.value,
            maxUDPPayloadSize: transportParameters[TransportParameterTypes.maxUDPPayloadSize]?
                .value,
            ackDelayExponent: transportParameters[TransportParameterTypes.ackDelayExponent]?.value,
            maxAckDelay: transportParameters[TransportParameterTypes.maxAckDelay]?.duration,
            activeConnectionIDLimit: transportParameters[
                TransportParameterTypes.activeConnectionIDLimit
            ]?.value,
            initialMaxData: transportParameters[TransportParameterTypes.initialMaxData]?.value,
            initialMaxStreamDataBidirectionalRemote: transportParameters[
                TransportParameterTypes.initialMaxStreamDataBidirectionalRemote
            ]?.value,
            initialMaxStreamDataBidirectionalLocal: transportParameters[
                TransportParameterTypes.initialMaxStreamDataBidirectionalLocal
            ]?.value,
            initialMaxStreamDataUnidirectional: transportParameters[
                TransportParameterTypes.initialMaxStreamDataUnidirectional
            ]?.value,
            initialMaxStreamsBidirectional: transportParameters[
                TransportParameterTypes.initialMaxStreamsBidirectional
            ]?.value,
            initialMaxStreamsUnidirectional: transportParameters[
                TransportParameterTypes.initialMaxStreamsUnidirectional
            ]?.value,
            preferredAddress: transportParameters[TransportParameterTypes.preferredAddress]?
                .preferredAddress,
            timestamp: timestamp
        )
    }

    public func setTopLevelObjectEntry(_ key: String, to value: String) {
        self.topLevelObject[key] = value
    }

    func dumpData(forFlowType flowType: QLogFlowType?) -> Data? {
        let vantagePointObject = [
            "type": "network", "flow": flowType?.rawValue,
        ]

        var traceObject: [String: Any] = ["vantage_point": vantagePointObject]

        let eventFieldsObject: [String] = [
            "time", "CATEGORY", "EVENT_TYPE", "DATA",
        ]
        traceObject["event_fields"] = eventFieldsObject

        var eventsArray: [Any] = []
        for event in eventsList {
            eventsArray.append(event.eventData())
        }
        eventsList.removeAll()

        traceObject["events"] = eventsArray

        let configurationObject = ["time_units": "us"]
        traceObject["configuration"] = configurationObject

        let traceList = [traceObject]
        topLevelObject["traces"] = traceList
        if let jsonData = try? JSONSerialization.data(withJSONObject: topLevelObject) {
            return jsonData
        } else {
            let topLevelObject = topLevelObject
            Logger.proto.error("Error serializing JSON: \(topLevelObject)")
            return nil
        }
    }

    // This is used with unit tests, therefore it needs to operate the same as dumpJSONToFile().
    // Therefore we use the common dumpData(forFlowType:) for both routines.
    public func dumpJSONString(forFlowType flowType: QLogFlowType?) -> String? {
        guard let jsonData = dumpData(forFlowType: flowType) else {
            return nil
        }
        let jsonString = String(data: jsonData, encoding: String.defaultCStringEncoding)
        return jsonString
    }

    public func dumpJSONToFile(
        atPath filename: String,
        forFlowType flowType: QLogFlowType?
    ) {
        guard let jsonData = dumpData(forFlowType: flowType) else {
            return
        }
        let _ = FileManager.default.createFile(atPath: filename, contents: jsonData)
    }
}
#else
final class QLog {}

#endif  // !NETWORK_EMBEDDED
#endif
