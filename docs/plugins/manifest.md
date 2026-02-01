---
summary: "Plugin manifest + JSON schema requirements (strict config validation)"
read_when:
  - You are building a OpenClaw plugin
  - You need to ship a plugin config schema or debug plugin validation errors
title: "Plugin Manifest"
---

# Plugin manifest (openclaw.plugin.json)

Every plugin **must** ship a `openclaw.plugin.json` file in the **plugin root**.
OpenClaw uses this manifest to validate configuration **without executing plugin
code**. Missing or invalid manifests are treated as plugin errors and block
config validation.

See the full plugin system guide: [Plugins](/plugin).

## Required fields

```json
{
  "id": "voice-call",
  "configSchema": {
    "type": "object",
    "additionalProperties": false,
    "properties": {}
  }
}
```

Required keys:

- `id` (string): canonical plugin id.
- `configSchema` (object): JSON Schema for plugin config (inline).

Optional keys:

- `kind` (string): plugin kind (example: `"memory"`).
- `channels` (array): channel ids registered by this plugin (example: `["matrix"]`).
- `providers` (array): provider ids registered by this plugin.
- `skills` (array): skill directories to load (relative to the plugin root).
- `name` (string): display name for the plugin.
- `description` (string): short plugin summary.
- `uiHints` (object): config field labels/placeholders/sensitive flags for UI rendering.
- `version` (string): plugin version (informational).
- `security` (object): security metadata for verification (see below).

## JSON Schema requirements

- **Every plugin must ship a JSON Schema**, even if it accepts no config.
- An empty schema is acceptable (for example, `{ "type": "object", "additionalProperties": false }`).
- Schemas are validated at config read/write time, not at runtime.

## Validation behavior

- Unknown `channels.*` keys are **errors**, unless the channel id is declared by
  a plugin manifest.
- `plugins.entries.<id>`, `plugins.allow`, `plugins.deny`, and `plugins.slots.*`
  must reference **discoverable** plugin ids. Unknown ids are **errors**.
- If a plugin is installed but has a broken or missing manifest or schema,
  validation fails and Doctor reports the plugin error.
- If plugin config exists but the plugin is **disabled**, the config is kept and
  a **warning** is surfaced in Doctor + logs.

## Security metadata

Plugins can include security metadata for verification by the skill-guardian module.

```json
{
  "id": "my-plugin",
  "configSchema": { "type": "object", "additionalProperties": false },
  "security": {
    "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "signature": "base64-encoded-ed25519-signature",
    "signedBy": "publisher-key-id"
  }
}
```

Security fields:

- `hash` (string): SHA-256 content hash of the plugin entry point, prefixed with `sha256:`.
- `signature` (string): Base64-encoded Ed25519 signature of the canonical manifest.
- `signedBy` (string): Key ID of the signing key (must match a trusted key in config).

When `plugins.security.mode` is `strict`, plugins without valid security metadata
are blocked (except bundled plugins when `trustBundled` is true).

See [Plugin Security](/plugin#plugin-security-skill-guardian) for full configuration.

## Notes

- The manifest is **required for all plugins**, including local filesystem loads.
- Runtime still loads the plugin module separately; the manifest is only for
  discovery + validation.
- If your plugin depends on native modules, document the build steps and any
  package-manager allowlist requirements (for example, pnpm `allow-build-scripts`
  - `pnpm rebuild <package>`).
