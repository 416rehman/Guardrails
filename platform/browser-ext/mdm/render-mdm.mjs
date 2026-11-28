// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const DEFAULT_CHROME_EXTENSION_ID = "grdrkjhmpfghijklmno";
export const DEFAULT_EDGE_EXTENSION_ID = "grdrkjhmpfghijklmno";
export const DEFAULT_FIREFOX_EXTENSION_ID = "adr@guardrails.dev";
export const DEFAULT_NATIVE_HOST_NAME = "grdr.browser";
export const DEFAULT_ORG_ID = "org-corp-prod";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const DESTINATIONS_CATALOG = JSON.parse(
  readFileSync(resolve(SCRIPT_DIR, "../data/ai-destinations.json"), "utf8"),
);

export function xmlEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export function validateMirrorOrigin(origin) {
  const raw = String(origin || "https://guardrails.internal:8443").trim();
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`GRDR-EXT-0904 Invalid mirrorOrigin URL: ${raw}`);
  }
  const host = parsed.hostname.toLowerCase();
  const isLoopback = host === "127.0.0.1" || host === "localhost" || host === "::1";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopback)) {
    throw new Error(
      `GRDR-EXT-0905 Unsafe mirrorOrigin scheme (${parsed.protocol}); use https or loopback http`,
    );
  }
  return parsed.origin;
}

function getCopilotAllowHosts() {
  const copilot = (DESTINATIONS_CATALOG.destinations || []).find(
    (d) => d.id === "m365-copilot",
  );
  return copilot?.hosts ?? ["copilot.microsoft.com", "m365.cloud.microsoft"];
}

function buildManagedStoragePayload(opts, normalizedOrigin) {
  return {
    organizationId: opts.orgId || DEFAULT_ORG_ID,
    serverOrigin: normalizedOrigin,
    failClosedOnDegraded: Boolean(opts.failClosedOnDegraded),
    blockAnonymousSessions: opts.blockAnonymousSessions !== false,
    tenantRestrictions: opts.tenantRestrictions || {
      anthropic: ["org-corp-prod"],
      openai_chatgpt: ["ws-corp-enterprise"],
      google_workspace: ["corp.example"],
      github_enterprise: ["corp-enterprise"],
    },
    appModes: opts.appModes || {
      chatgpt: "ask",
      "claude-web": "ask",
      perplexity: "block",
    },
  };
}

export function renderBrowserMdmArtifact(format, options = {}) {
  const mirrorOrigin = validateMirrorOrigin(options.mirrorOrigin);
  const chromeId = String(options.chromeExtensionId || DEFAULT_CHROME_EXTENSION_ID).trim();
  const edgeId = String(options.edgeExtensionId || DEFAULT_EDGE_EXTENSION_ID).trim();
  const firefoxId = String(options.firefoxExtensionId || DEFAULT_FIREFOX_EXTENSION_ID).trim();
  const version = String(options.extensionVersion || "0.1.0").trim();
  const crxUpdateUrl = `${mirrorOrigin}/extensions/chrome-update.xml`;
  const crxDownloadUrl = `${mirrorOrigin}/extensions/guardrails-chrome-${version}.crx`;
  const firefoxXpiUrl = `${mirrorOrigin}/extensions/guardrails-firefox-${version}.xpi`;
  const hostPathWin = String(
    options.nativeHostPathWin || "C:\\Program Files\\Guardrails\\grdr-hook.exe",
  );
  const hostPathUnix = String(options.nativeHostPathUnix || "/usr/local/bin/grdr-hook");
  const managed = buildManagedStoragePayload(options, mirrorOrigin);

  switch (format) {
    case "chrome_enterprise":
      return JSON.stringify(
        {
          schema: "grdr.mdm.chrome_enterprise.v1",
          notes:
            "Merge ExtensionSettings keys additively under HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings without overwriting unrelated third-party extension entries.",
          policies: {
            ExtensionSettings: {
              [chromeId]: {
                installation_mode: "force_installed",
                update_url: crxUpdateUrl,
                override_update_url: true,
                toolbar_pin: "force_pinned",
                blocked_install_message:
                  "Guardrails browser policy is managed by your security administrator.",
              },
            },
            RemoteDebuggingAllowed: false,
            DeveloperToolsAvailability: 2,
            IncognitoModeAvailability: 1,
            GeminiActOnWebSettings: 1,
            ManagedStorage: {
              [chromeId]: managed,
            },
          },
        },
        null,
        2,
      );

    case "edge_enterprise":
      return JSON.stringify(
        {
          schema: "grdr.mdm.edge_enterprise.v1",
          notes:
            "Apply under HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge and preserve existing non-Guardrails ExtensionSettings entries.",
          policies: {
            ExtensionSettings: {
              [edgeId]: {
                installation_mode: "force_installed",
                update_url: crxUpdateUrl,
                override_update_url: true,
                toolbar_pin: "force_pinned",
              },
            },
            RemoteDebuggingAllowed: false,
            InPrivateModeAvailability: 1,
            AgentProfileEnabled: false,
            CopilotBrowserUseAllowList: getCopilotAllowHosts(),
            CopilotBrowserUseBlockList: ["*"],
            ManagedStorage: {
              [edgeId]: managed,
            },
          },
        },
        null,
        2,
      );

    case "chrome_update_xml":
      return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">',
        '  <app appid="' + xmlEscape(chromeId) + '">',
        '    <updatecheck codebase="' +
          xmlEscape(crxDownloadUrl) +
          '" version="' +
          xmlEscape(version) +
          '" />',
        "  </app>",
        "</gupdate>",
      ].join("\n");

    case "firefox_policies":
      return JSON.stringify(
        {
          policies: {
            ExtensionSettings: {
              [firefoxId]: {
                installation_mode: "force_installed",
                install_url: firefoxXpiUrl,
                private_browsing: true,
              },
            },
            DisableDeveloperTools: true,
            "3rdparty": {
              Extensions: {
                [firefoxId]: managed,
              },
            },
          },
        },
        null,
        2,
      );

    case "firefox_admx":
      return [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<policyDefinitions xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">',
        "  <policyNamespaces>",
        '    <target prefix="guardrailsfirefox" namespace="Guardrails.Policies.Firefox" />',
        '    <using prefix="windows" namespace="Microsoft.Policies.Windows" />',
        "  </policyNamespaces>",
        '  <resources minRequiredRevision="1.0" />',
        "  <categories>",
        '    <category name="GuardrailsBrowser" displayName="$(string.GuardrailsBrowser)" />',
        "  </categories>",
        "  <policies>",
        '    <policy name="ForceInstallExtensionSettings" class="Machine" displayName="$(string.ForceInstallExtensionSettings)" explainText="$(string.ForceInstallExtensionSettings_Help)" key="SOFTWARE\\Policies\\Mozilla\\Firefox" valueName="ExtensionSettings">',
        '      <parentCategory ref="GuardrailsBrowser" />',
        '      <supportedOn ref="windows:SUPPORTED_WindowsVista" />',
        "      <elements>",
        '        <multiText id="ExtensionSettingsJson" valueName="ExtensionSettings" />',
        "      </elements>",
        "    </policy>",
        "  </policies>",
        "</policyDefinitions>",
      ].join("\n");

    case "firefox_adml":
      return [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<policyDefinitionResources xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">',
        "  <displayName>Guardrails ADR Firefox Extension Policy</displayName>",
        "  <description>Configures force-installed Guardrails ADR browser extension and hardened developer settings for Mozilla Firefox.</description>",
        "  <resources>",
        "    <stringTable>",
        '      <string id="GuardrailsBrowser">Guardrails Browser Protection</string>',
        '      <string id="ForceInstallExtensionSettings">Force-install Guardrails ADR Firefox Extension</string>',
        '      <string id="ForceInstallExtensionSettings_Help">Install ' +
          xmlEscape(firefoxId) +
          " from " +
          xmlEscape(firefoxXpiUrl) +
          " via Mozilla ExtensionSettings policy.</string>",
        "    </stringTable>",
        "  </resources>",
        "</policyDefinitionResources>",
      ].join("\n");

    case "macos_mobileconfig":
      return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0">',
        "<dict>",
        "  <key>PayloadContent</key>",
        "  <array>",
        "    <dict>",
        "      <key>PayloadType</key><string>com.google.Chrome</string>",
        "      <key>PayloadIdentifier</key><string>dev.guardrails.browser.chrome</string>",
        "      <key>PayloadUUID</key><string>7f9a8d2c-2b4d-4d8a-9c5e-100000000001</string>",
        "      <key>PayloadVersion</key><integer>1</integer>",
        "      <key>ExtensionInstallForcelist</key>",
        "      <array>",
        "        <string>" + xmlEscape(chromeId) + ";" + xmlEscape(crxUpdateUrl) + "</string>",
        "      </array>",
        "      <key>RemoteDebuggingAllowed</key><false/>",
        "      <key>DeveloperToolsAvailability</key><integer>2</integer>",
        "      <key>IncognitoModeAvailability</key><integer>1</integer>",
        "    </dict>",
        "    <dict>",
        "      <key>PayloadType</key><string>org.mozilla.firefox</string>",
        "      <key>PayloadIdentifier</key><string>dev.guardrails.browser.firefox</string>",
        "      <key>PayloadUUID</key><string>7f9a8d2c-2b4d-4d8a-9c5e-100000000002</string>",
        "      <key>PayloadVersion</key><integer>1</integer>",
        "      <key>EnterprisePoliciesEnabled</key><true/>",
        "      <key>ExtensionSettings</key>",
        "      <dict>",
        "        <key>" + xmlEscape(firefoxId) + "</key>",
        "        <dict>",
        "          <key>installation_mode</key><string>force_installed</string>",
        "          <key>install_url</key><string>" + xmlEscape(firefoxXpiUrl) + "</string>",
        "          <key>private_browsing</key><true/>",
        "        </dict>",
        "      </dict>",
        "    </dict>",
        "  </array>",
        "  <key>PayloadDisplayName</key><string>Guardrails Browser Extension Policy</string>",
        "  <key>PayloadIdentifier</key><string>dev.guardrails.browser.profile</string>",
        "  <key>PayloadType</key><string>Configuration</string>",
        "  <key>PayloadUUID</key><string>7f9a8d2c-2b4d-4d8a-9c5e-100000000000</string>",
        "  <key>PayloadVersion</key><integer>1</integer>",
        "</dict>",
        "</plist>",
      ].join("\n");

    case "intune_oma_uri": {
      const chromeSettingsJson = xmlEscape(
        JSON.stringify({
          [chromeId]: {
            installation_mode: "force_installed",
            update_url: crxUpdateUrl,
            override_update_url: true,
          },
        }),
      );
      const edgeSettingsJson = xmlEscape(
        JSON.stringify({
          [edgeId]: {
            installation_mode: "force_installed",
            update_url: crxUpdateUrl,
            override_update_url: true,
          },
        }),
      );
      return JSON.stringify(
        {
          schema: "grdr.mdm.intune_oma_uri.v1",
          settings: [
            {
              name: "Chrome Force-Install Guardrails Extension (ExtensionSettings)",
              omaUri:
                "./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome~Extensions/ExtensionSettings",
              dataType: "String",
              value: '<enabled/><data id="ExtensionSettings" value=\'' + chromeSettingsJson + "'/>",
            },
            {
              name: "Edge Force-Install Guardrails Extension (ExtensionSettings)",
              omaUri:
                "./Device/Vendor/MSFT/Policy/Config/Edge~Policy~microsoft_edge~Extensions/ExtensionSettings",
              dataType: "String",
              value: '<enabled/><data id="ExtensionSettings" value=\'' + edgeSettingsJson + "'/>",
            },
            {
              name: "Disable Chrome Remote Debugging",
              omaUri:
                "./Device/Vendor/MSFT/Policy/Config/Chrome~Policy~googlechrome/RemoteDebuggingAllowed",
              dataType: "String",
              value: "<disabled/>",
            },
          ],
          nativeMessagingRegistryKeyWin: `HKLM\\SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\${DEFAULT_NATIVE_HOST_NAME}`,
          nativeHostExecutableWin: hostPathWin,
        },
        null,
        2,
      );
    }

    case "hexnode_policy":
      return JSON.stringify(
        {
          schema: "grdr.mdm.hexnode.v1",
          profileName: "Guardrails ADR Browser Protection",
          chromeExtensionForcelist: [`${chromeId};${crxUpdateUrl}`],
          edgeExtensionForcelist: [`${edgeId};${crxUpdateUrl}`],
          firefoxExtensionId: firefoxId,
          firefoxXpiUrl,
          managedConfiguration: managed,
        },
        null,
        2,
      );

    case "native_messaging_chrome":
      return JSON.stringify(
        {
          name: DEFAULT_NATIVE_HOST_NAME,
          description: "Guardrails ADR native policy verdict host for Chromium browsers",
          path: hostPathUnix,
          type: "stdio",
          allowed_origins: [`chrome-extension://${chromeId}/`],
        },
        null,
        2,
      );

    case "native_messaging_firefox":
      return JSON.stringify(
        {
          name: DEFAULT_NATIVE_HOST_NAME,
          description: "Guardrails ADR native policy verdict host for Mozilla Firefox",
          path: hostPathUnix,
          type: "stdio",
          allowed_extensions: [firefoxId],
        },
        null,
        2,
      );

    default:
      throw new Error(`GRDR-EXT-0903 Unsupported MDM template format: ${format}`);
  }
}

export const STATIC_MDM_OUTPUTS = [
  ["chrome_enterprise", "chrome-enterprise.json"],
  ["edge_enterprise", "edge-enterprise.json"],
  ["chrome_update_xml", "chrome-update-manifest.xml"],
  ["firefox_policies", "firefox-policies.json"],
  ["firefox_admx", "mozilla-grdr-browser.admx"],
  ["firefox_adml", "en-US/mozilla-grdr-browser.adml"],
  ["macos_mobileconfig", "jamf-macos.mobileconfig"],
  ["intune_oma_uri", "intune-oma-uri.json"],
  ["hexnode_policy", "hexnode-policy.json"],
  ["native_messaging_chrome", "grdr.browser.native-messaging.chrome.json"],
  ["native_messaging_firefox", "grdr.browser.native-messaging.firefox.json"],
];

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const formatIdx = args.indexOf("--format");
  const originIdx = args.indexOf("--origin");
  const orgIdx = args.indexOf("--org");
  const format = formatIdx >= 0 ? args[formatIdx + 1] : "chrome_enterprise";
  const mirrorOrigin = originIdx >= 0 ? args[originIdx + 1] : "https://guardrails.internal:8443";
  const orgId = orgIdx >= 0 ? args[orgIdx + 1] : DEFAULT_ORG_ID;
  process.stdout.write(`${renderBrowserMdmArtifact(format, { mirrorOrigin, orgId })}\n`);
}
