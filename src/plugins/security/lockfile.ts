/**
 * Plugin Lockfile Management
 *
 * HMAC-authenticated lockfile for plugin integrity verification.
 * Prevents tampering with pinned plugin hashes.
 */

import { createHmac, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import type { LockedPlugin, PluginLockfile, PluginOrigin, SecuritySeverity } from "./types.js";

const LOCKFILE_VERSION = 2;
const HMAC_ALGORITHM = "sha256";
const SECRET_KEY_LENGTH = 32;

// =============================================================================
// Lockfile Operations
// =============================================================================

/**
 * Load lockfile from disk.
 * Returns null if lockfile doesn't exist or is invalid.
 */
export function loadLockfile(lockfilePath: string): PluginLockfile | null {
  if (!fs.existsSync(lockfilePath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(lockfilePath, "utf-8");
    const lockfile = JSON.parse(content) as PluginLockfile;

    // Validate version
    if (lockfile.version !== LOCKFILE_VERSION) {
      return null;
    }

    return lockfile;
  } catch {
    return null;
  }
}

/**
 * Save lockfile to disk.
 * Regenerates HMAC before saving.
 */
export function saveLockfile(lockfilePath: string, lockfile: PluginLockfile, secret: string): void {
  // Ensure directory exists
  const dir = path.dirname(lockfilePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  // Update HMAC
  lockfile.hmac = computeLockfileHmac(lockfile, secret);
  lockfile.generatedAt = new Date().toISOString();

  // Write atomically
  const tempPath = `${lockfilePath}.tmp.${process.pid}`;
  fs.writeFileSync(tempPath, JSON.stringify(lockfile, null, 2), { mode: 0o600 });
  fs.renameSync(tempPath, lockfilePath);
}

/**
 * Create a new empty lockfile.
 */
export function createLockfile(): PluginLockfile {
  return {
    version: LOCKFILE_VERSION,
    generatedAt: new Date().toISOString(),
    hmac: "",
    plugins: {},
  };
}

// =============================================================================
// HMAC Verification
// =============================================================================

/**
 * Verify lockfile HMAC.
 */
export function verifyLockfileHmac(lockfile: PluginLockfile, secret: string): boolean {
  const expected = computeLockfileHmac(lockfile, secret);
  return constantTimeCompare(lockfile.hmac, expected);
}

/**
 * Compute HMAC for lockfile.
 */
function computeLockfileHmac(lockfile: PluginLockfile, secret: string): string {
  // Create canonical JSON of plugins (sorted keys, no whitespace)
  const pluginIds = Object.keys(lockfile.plugins).sort();
  const canonical: Record<string, LockedPlugin> = {};
  for (const id of pluginIds) {
    canonical[id] = lockfile.plugins[id];
  }

  const data = JSON.stringify(canonical);
  return createHmac(HMAC_ALGORITHM, secret).update(data).digest("hex");
}

/**
 * Constant-time string comparison.
 */
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

// =============================================================================
// Secret Key Management
// =============================================================================

/**
 * Load or create the lockfile secret key.
 */
export function loadOrCreateSecret(secretPath: string): string {
  // Ensure directory exists
  const dir = path.dirname(secretPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  if (fs.existsSync(secretPath)) {
    return fs.readFileSync(secretPath, "utf-8").trim();
  }

  // Generate new secret
  const secret = randomBytes(SECRET_KEY_LENGTH).toString("hex");
  fs.writeFileSync(secretPath, secret, { mode: 0o600 });

  return secret;
}

/**
 * Get default secret key path.
 */
export function getDefaultSecretPath(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
  return path.join(home, ".openclaw", "secrets", "lockfile.key");
}

/**
 * Get default lockfile path.
 */
export function getDefaultLockfilePath(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
  return path.join(home, ".openclaw", "plugins.lock");
}

// =============================================================================
// Plugin Pinning
// =============================================================================

/**
 * Pin a plugin to the lockfile.
 */
export function pinPlugin(
  lockfile: PluginLockfile,
  params: {
    id: string;
    version: string;
    source: string;
    origin: PluginOrigin;
    contentHash: string;
    manifestHash: string;
    signatureVerified?: boolean;
    signedBy?: string;
    scanFindings?: number;
    scanHighest?: SecuritySeverity | "none";
  },
): void {
  const now = new Date().toISOString();

  lockfile.plugins[params.id] = {
    version: params.version,
    source: params.source,
    origin: params.origin,
    contentHash: params.contentHash,
    manifestHash: params.manifestHash,
    signatureVerified: params.signatureVerified ?? false,
    signedBy: params.signedBy,
    pinnedAt: now,
    lastVerified: now,
    scanFindings: params.scanFindings,
    scanHighest: params.scanHighest,
  };
}

/**
 * Unpin a plugin from the lockfile.
 */
export function unpinPlugin(lockfile: PluginLockfile, id: string): boolean {
  if (id in lockfile.plugins) {
    delete lockfile.plugins[id];
    return true;
  }
  return false;
}

/**
 * Update last verified timestamp for a plugin.
 */
export function updateLastVerified(lockfile: PluginLockfile, id: string): boolean {
  if (id in lockfile.plugins) {
    lockfile.plugins[id].lastVerified = new Date().toISOString();
    return true;
  }
  return false;
}

// =============================================================================
// Plugin Verification
// =============================================================================

/**
 * Result of plugin verification against lockfile.
 */
export type LockfileVerifyResult = {
  /** Plugin found in lockfile */
  found: boolean;

  /** Verification passed */
  ok: boolean;

  /** Reason for failure */
  reason?: string;

  /** Locked plugin entry */
  locked?: LockedPlugin;

  /** Mismatches detected */
  mismatches?: {
    contentHash?: { expected: string; actual: string };
    manifestHash?: { expected: string; actual: string };
    version?: { expected: string; actual: string };
    source?: { expected: string; actual: string };
  };
};

/**
 * Verify a plugin against the lockfile.
 */
export function verifyPluginAgainstLockfile(
  lockfile: PluginLockfile,
  params: {
    id: string;
    version?: string;
    source: string;
    contentHash: string;
    manifestHash: string;
  },
): LockfileVerifyResult {
  const locked = lockfile.plugins[params.id];

  if (!locked) {
    return {
      found: false,
      ok: false,
      reason: "plugin not in lockfile",
    };
  }

  const mismatches: LockfileVerifyResult["mismatches"] = {};

  // Check content hash
  if (locked.contentHash !== params.contentHash) {
    mismatches.contentHash = {
      expected: locked.contentHash,
      actual: params.contentHash,
    };
  }

  // Check manifest hash
  if (locked.manifestHash !== params.manifestHash) {
    mismatches.manifestHash = {
      expected: locked.manifestHash,
      actual: params.manifestHash,
    };
  }

  // Check version (optional - warn only)
  if (params.version && locked.version !== params.version) {
    mismatches.version = {
      expected: locked.version,
      actual: params.version,
    };
  }

  // Check source path
  if (locked.source !== params.source) {
    mismatches.source = {
      expected: locked.source,
      actual: params.source,
    };
  }

  const hasCriticalMismatch = mismatches.contentHash || mismatches.manifestHash;

  if (hasCriticalMismatch) {
    return {
      found: true,
      ok: false,
      reason: mismatches.contentHash
        ? "content hash mismatch"
        : "manifest hash mismatch",
      locked,
      mismatches,
    };
  }

  return {
    found: true,
    ok: true,
    locked,
    mismatches: Object.keys(mismatches).length > 0 ? mismatches : undefined,
  };
}

// =============================================================================
// Lockfile Queries
// =============================================================================

/**
 * Get all pinned plugin IDs.
 */
export function getPinnedPluginIds(lockfile: PluginLockfile): string[] {
  return Object.keys(lockfile.plugins).sort();
}

/**
 * Get locked plugin entry by ID.
 */
export function getLockedPlugin(lockfile: PluginLockfile, id: string): LockedPlugin | undefined {
  return lockfile.plugins[id];
}

/**
 * Check if a plugin is pinned.
 */
export function isPluginPinned(lockfile: PluginLockfile, id: string): boolean {
  return id in lockfile.plugins;
}

/**
 * Get plugins that haven't been verified recently.
 */
export function getStalePlugins(lockfile: PluginLockfile, maxAgeDays: number): string[] {
  const cutoff = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
  const stale: string[] = [];

  for (const [id, plugin] of Object.entries(lockfile.plugins)) {
    const lastVerified = new Date(plugin.lastVerified).getTime();
    if (lastVerified < cutoff) {
      stale.push(id);
    }
  }

  return stale;
}

/**
 * Get plugins with security findings.
 */
export function getPluginsWithFindings(
  lockfile: PluginLockfile,
  minSeverity?: SecuritySeverity,
): Array<{ id: string; findings: number; highest: SecuritySeverity | "none" }> {
  const severityOrder: Record<string, number> = {
    none: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };

  const minLevel = minSeverity ? severityOrder[minSeverity] : 1;
  const result: Array<{ id: string; findings: number; highest: SecuritySeverity | "none" }> = [];

  for (const [id, plugin] of Object.entries(lockfile.plugins)) {
    if (plugin.scanFindings && plugin.scanFindings > 0) {
      const highestLevel = severityOrder[plugin.scanHighest ?? "none"];
      if (highestLevel >= minLevel) {
        result.push({
          id,
          findings: plugin.scanFindings,
          highest: plugin.scanHighest ?? "none",
        });
      }
    }
  }

  return result.sort(
    (a, b) => severityOrder[b.highest] - severityOrder[a.highest] || b.findings - a.findings,
  );
}

// =============================================================================
// Migration
// =============================================================================

/**
 * Migrate lockfile from older versions.
 */
export function migrateLockfile(oldLockfile: unknown): PluginLockfile | null {
  if (!oldLockfile || typeof oldLockfile !== "object") {
    return null;
  }

  const obj = oldLockfile as Record<string, unknown>;

  // Version 1 -> Version 2
  if (obj.version === 1) {
    const migrated = createLockfile();

    if (obj.plugins && typeof obj.plugins === "object") {
      const oldPlugins = obj.plugins as Record<string, unknown>;

      for (const [id, plugin] of Object.entries(oldPlugins)) {
        if (plugin && typeof plugin === "object") {
          const p = plugin as Record<string, unknown>;
          migrated.plugins[id] = {
            version: String(p.version ?? "0.0.0"),
            source: String(p.source ?? ""),
            origin: (p.origin as PluginOrigin) ?? "config",
            contentHash: String(p.contentHash ?? ""),
            manifestHash: String(p.manifestHash ?? p.contentHash ?? ""),
            signatureVerified: Boolean(p.signatureVerified),
            signedBy: p.signedBy as string | undefined,
            pinnedAt: String(p.pinnedAt ?? p.installedAt ?? new Date().toISOString()),
            lastVerified: String(p.lastVerified ?? new Date().toISOString()),
          };
        }
      }
    }

    return migrated;
  }

  // Already current version
  if (obj.version === LOCKFILE_VERSION) {
    return obj as PluginLockfile;
  }

  return null;
}
