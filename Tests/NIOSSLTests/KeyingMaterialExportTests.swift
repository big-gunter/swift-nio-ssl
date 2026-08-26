//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSL

/// Covers `NIOSSLHandler.exportKeyingMaterial(label:context:numberOfBytes:)`, the RFC 5705
/// keying-material exporter added on top of `SSL_export_keying_material`.
final class KeyingMaterialExportTests: XCTestCase {
    private static let certAndKey = generateSelfSignedCert()
    static var cert: NIOSSLCertificate { Self.certAndKey.0 }
    static var key: NIOSSLPrivateKey { Self.certAndKey.1 }

    override class func setUp() {
        super.setUp()
        guard boringSSLIsInitialized else { fatalError() }
    }

    /// The whole point of RFC 5705 exporters is that both ends of one TLS connection derive
    /// *the same* value from *the same* label/context/length, entirely independently, without
    /// exchanging anything else over the wire for it. That agreement is what this test actually
    /// checks -- not just "the call returns bytes." Uses `BackToBackEmbeddedChannel` (as
    /// `testObtainingTLSVersionOnClientChannel` above does for `tlsVersion`) so the handshake is
    /// driven synchronously and deterministically -- no real sockets, no timing races.
    func testClientAndServerAgreeOnExportedKeyingMaterial() throws {
        let b2b = BackToBackEmbeddedChannel()

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([Self.cert])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(Self.cert)],
            privateKey: .privateKey(Self.key)
        )
        serverConfig.certificateVerification = .none

        let clientContext = try NIOSSLContext(configuration: clientConfig)
        let serverContext = try NIOSSLContext(configuration: serverConfig)

        try b2b.client.pipeline.syncOperations.addHandlers([
            try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost"),
            HandshakeCompletedHandler(),
        ])
        try b2b.server.pipeline.syncOperations.addHandlers([
            NIOSSLServerHandler(context: serverContext),
            HandshakeCompletedHandler(),
        ])

        try b2b.connectInMemory()

        let label = Array("EXPORTER-test-label".utf8)
        let exportContext = Array("some-context".utf8)
        let numberOfBytes = 48

        let clientMaterial = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: label,
            context: exportContext,
            numberOfBytes: numberOfBytes
        )
        let serverMaterial = try b2b.server.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: label,
            context: exportContext,
            numberOfBytes: numberOfBytes
        )

        XCTAssertEqual(clientMaterial.count, numberOfBytes)
        XCTAssertEqual(clientMaterial, serverMaterial)

        // A different label must not collide with the first one -- rules out a stub that
        // ignores its arguments and always returns the same (or all-zero) bytes.
        let differentLabelMaterial = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: Array("EXPORTER-different-label".utf8),
            context: exportContext,
            numberOfBytes: numberOfBytes
        )
        XCTAssertNotEqual(clientMaterial, differentLabelMaterial)

        // `context: nil` (use_context=0) must be handled distinctly from an empty context
        // array (use_context=1, context_len=0) without throwing, per the documented BoringSSL
        // behavior for connections negotiated below TLS 1.3.
        let noContextMaterial = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: label,
            context: nil,
            numberOfBytes: numberOfBytes
        )
        XCTAssertEqual(noContextMaterial.count, numberOfBytes)
    }
}
