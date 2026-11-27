# Guardrails Browser Extension MDM Deployment Templates

Use `render-mdm.mjs` or the templates in this directory to force-install the Guardrails MV3 extension and register the `grdr.browser` Native Messaging host across managed endpoints.

## Merge hygiene for Chromium policies
Never overwrite an existing `ExtensionInstallForcelist` array or third-party keys inside `ExtensionSettings`. Merge the Guardrails extension ID entry additively so existing enterprise security or SSO extensions stay intact.

## Templates included
- `chrome-enterprise.json` and `chrome-update-manifest.xml`: Chrome/Brave force-install, internal CRX3 update mirror URL, `RemoteDebuggingAllowed=false`, `IncognitoModeAvailability=1`, and managed storage payload.
- `edge-enterprise.json`: Edge force-install plus Copilot browser controls (`CopilotBrowserUseAllowList`, `CopilotBrowserUseBlockList`, `AgentProfileEnabled=false`).
- `firefox-policies.json`, `mozilla-grdr-browser.admx`, and `en-US/mozilla-grdr-browser.adml`: Firefox Enterprise policy JSON and Windows Active Directory GPO definitions for `adr@guardrails.dev`.
- `jamf-macos.mobileconfig`, `intune-oma-uri.json`, and `hexnode-policy.json`: MDM profile payloads for macOS and Windows.
- `grdr.browser.native-messaging.chrome.json` and `grdr.browser.native-messaging.firefox.json`: Native Messaging stdio manifests for `grdr-hook`.

## Custom mirror rendering
```bash
node platform/browser-ext/mdm/render-mdm.mjs --format chrome_enterprise --origin https://mirror.corp.internal:8443 --org org_corp
```
