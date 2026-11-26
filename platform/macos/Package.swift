// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "GrdrMacOSExtensions",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "GrdrContainerApp", targets: ["ContainerApp"]),
        .library(name: "GrdrNetworkExtension", targets: ["NetworkExtension"]),
        .library(name: "GrdrEndpointSecurityExtension", targets: ["EndpointSecurityExtension"])
    ],
    targets: [
        .systemLibrary(
            name: "GrdrSensorMacOSBridge",
            path: "Bridge"
        ),
        .target(
            name: "ContainerApp",
            dependencies: ["GrdrSensorMacOSBridge"],
            path: "ContainerApp",
            exclude: ["Info.plist", "GuardrailsADR.entitlements"]
        ),
        .target(
            name: "NetworkExtension",
            dependencies: ["GrdrSensorMacOSBridge"],
            path: "NetworkExtension",
            exclude: ["Info.plist", "NetworkExtension.entitlements"]
        ),
        .target(
            name: "EndpointSecurityExtension",
            dependencies: ["GrdrSensorMacOSBridge"],
            path: "EndpointSecurityExtension",
            exclude: ["Info.plist", "EndpointSecurity.entitlements"]
        )
    ]
)
