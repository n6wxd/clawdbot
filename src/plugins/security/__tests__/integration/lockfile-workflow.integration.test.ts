/**
 * Lockfile Workflow Integration Tests
 *
 * Tests the full pin/verify cycle with HMAC-authenticated lockfile.
 */

import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { computeFileHash } from "../../hash.js";
import {
  createLockfile,
  getLockedPlugin,
  getPinnedPluginIds,
  getPluginsWithFindings,
  getStalePlugins,
  isPluginPinned,
  loadLockfile,
  loadOrCreateSecret,
  pinPlugin,
  saveLockfile,
  unpinPlugin,
  updateLastVerified,
  verifyLockfileHmac,
  verifyPluginAgainstLockfile,
} from "../../lockfile.js";
import { verifyPluginSecurity } from "../../verify.js";
import type { PluginLockfile, PluginOrigin } from "../../types.js";
import {
  cleanupTempDir,
  createPermissiveConfig,
  createSafePlugin,
  createTamperedPlugin,
  createTempDir,
  createTestLockfile,
  createUnsignedPlugin,
  createVerifyContext,
} from "./setup.js";

describe("lockfile-workflow", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir("lockfile-test-");
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("lockfile creation", () => {
    it("should create empty lockfile with correct structure", () => {
      const lockfile = createLockfile();

      expect(lockfile.version).toBe(2);
      expect(lockfile.generatedAt).toBeTruthy();
      expect(lockfile.hmac).toBe("");
      expect(lockfile.plugins).toEqual({});
    });

    it("should generate ISO timestamp", () => {
      const lockfile = createLockfile();

      // Should be valid ISO date
      const date = new Date(lockfile.generatedAt);
      expect(date.toString()).not.toBe("Invalid Date");
    });
  });

  describe("plugin pinning", () => {
    it("should pin a plugin with all metadata", () => {
      const lockfile = createLockfile();
      const plugin = createSafePlugin(tempDir);

      const contentHash = computeFileHash(plugin.entryPath).formatted;
      const manifestHash = computeFileHash(plugin.manifestPath).formatted;

      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: plugin.manifest.version,
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash,
        manifestHash,
        signatureVerified: false,
      });

      expect(lockfile.plugins[plugin.manifest.id]).toBeDefined();
      const pinned = lockfile.plugins[plugin.manifest.id];
      expect(pinned.version).toBe(plugin.manifest.version);
      expect(pinned.source).toBe(plugin.manifestPath);
      expect(pinned.origin).toBe("workspace");
      expect(pinned.contentHash).toBe(contentHash);
      expect(pinned.manifestHash).toBe(manifestHash);
      expect(pinned.signatureVerified).toBe(false);
      expect(pinned.pinnedAt).toBeTruthy();
      expect(pinned.lastVerified).toBeTruthy();
    });

    it("should update existing pin", () => {
      const lockfile = createLockfile();
      const plugin = createSafePlugin(tempDir);

      const contentHash1 = "sha256:" + "a".repeat(64);
      const contentHash2 = "sha256:" + "b".repeat(64);

      // Pin first time
      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: "1.0.0",
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash: contentHash1,
        manifestHash: contentHash1,
      });

      // Pin again with different hash (updated)
      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: "1.0.1",
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash: contentHash2,
        manifestHash: contentHash2,
      });

      expect(lockfile.plugins[plugin.manifest.id].version).toBe("1.0.1");
      expect(lockfile.plugins[plugin.manifest.id].contentHash).toBe(contentHash2);
    });

    it("should unpin a plugin", () => {
      const lockfile = createLockfile();
      const plugin = createSafePlugin(tempDir);

      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: "1.0.0",
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash: "sha256:" + "a".repeat(64),
        manifestHash: "sha256:" + "a".repeat(64),
      });

      expect(unpinPlugin(lockfile, plugin.manifest.id)).toBe(true);
      expect(lockfile.plugins[plugin.manifest.id]).toBeUndefined();
    });

    it("should return false when unpinning non-existent plugin", () => {
      const lockfile = createLockfile();
      expect(unpinPlugin(lockfile, "non-existent")).toBe(false);
    });
  });

  describe("HMAC verification", () => {
    it("should verify valid HMAC", () => {
      const lockfile = createLockfile();
      const secret = "test-secret-key";
      const plugin = createSafePlugin(tempDir);

      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: "1.0.0",
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash: "sha256:" + "a".repeat(64),
        manifestHash: "sha256:" + "a".repeat(64),
      });

      // Save will compute HMAC
      const lockfilePath = path.join(tempDir, "test.lock");
      saveLockfile(lockfilePath, lockfile, secret);

      // Load and verify
      const loaded = loadLockfile(lockfilePath)!;
      expect(verifyLockfileHmac(loaded, secret)).toBe(true);
    });

    it("should reject invalid HMAC", () => {
      const lockfile = createLockfile();
      const secret = "test-secret-key";
      const wrongSecret = "wrong-secret";
      const plugin = createSafePlugin(tempDir);

      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: "1.0.0",
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash: "sha256:" + "a".repeat(64),
        manifestHash: "sha256:" + "a".repeat(64),
      });

      const lockfilePath = path.join(tempDir, "test.lock");
      saveLockfile(lockfilePath, lockfile, secret);

      const loaded = loadLockfile(lockfilePath)!;
      expect(verifyLockfileHmac(loaded, wrongSecret)).toBe(false);
    });

    it("should detect tampered plugin data", () => {
      const lockfile = createLockfile();
      const secret = "test-secret-key";
      const plugin = createSafePlugin(tempDir);

      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: "1.0.0",
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash: "sha256:" + "a".repeat(64),
        manifestHash: "sha256:" + "a".repeat(64),
      });

      const lockfilePath = path.join(tempDir, "test.lock");
      saveLockfile(lockfilePath, lockfile, secret);

      // Tamper with the file
      const loaded = loadLockfile(lockfilePath)!;
      loaded.plugins[plugin.manifest.id].contentHash = "sha256:" + "b".repeat(64);

      // HMAC should no longer match
      expect(verifyLockfileHmac(loaded, secret)).toBe(false);
    });
  });

  describe("atomic file operations", () => {
    it("should save lockfile atomically using temp file", () => {
      const lockfile = createLockfile();
      const lockfilePath = path.join(tempDir, "plugins.lock");
      const secret = "secret";

      // Save should create the file
      saveLockfile(lockfilePath, lockfile, secret);
      expect(fs.existsSync(lockfilePath)).toBe(true);

      // No temp file should remain
      const files = fs.readdirSync(tempDir);
      const tempFiles = files.filter((f) => f.includes(".tmp."));
      expect(tempFiles).toHaveLength(0);
    });

    it("should create parent directory if needed", () => {
      const lockfile = createLockfile();
      const nestedPath = path.join(tempDir, "nested", "dir", "plugins.lock");
      const secret = "secret";

      saveLockfile(nestedPath, lockfile, secret);

      expect(fs.existsSync(nestedPath)).toBe(true);
    });

    it("should set correct file permissions", () => {
      const lockfile = createLockfile();
      const lockfilePath = path.join(tempDir, "plugins.lock");
      const secret = "secret";

      saveLockfile(lockfilePath, lockfile, secret);

      const stats = fs.statSync(lockfilePath);
      // Should be owner read/write only (0o600)
      expect((stats.mode & 0o777).toString(8)).toBe("600");
    });
  });

  describe("plugin verification against lockfile", () => {
    it("should verify matching plugin", () => {
      const plugin = createSafePlugin(tempDir);
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      const manifestHash = computeFileHash(plugin.manifestPath).formatted;

      const lockfile = createLockfile();
      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: plugin.manifest.version,
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash,
        manifestHash,
      });

      const result = verifyPluginAgainstLockfile(lockfile, {
        id: plugin.manifest.id,
        version: plugin.manifest.version,
        source: plugin.manifestPath,
        contentHash,
        manifestHash,
      });

      expect(result.found).toBe(true);
      expect(result.ok).toBe(true);
      expect(result.locked).toBeDefined();
    });

    it("should detect content hash mismatch", () => {
      const plugin = createSafePlugin(tempDir);
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      const manifestHash = computeFileHash(plugin.manifestPath).formatted;

      const lockfile = createLockfile();
      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: plugin.manifest.version,
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash,
        manifestHash,
      });

      // Verify with different content hash (file changed)
      const result = verifyPluginAgainstLockfile(lockfile, {
        id: plugin.manifest.id,
        version: plugin.manifest.version,
        source: plugin.manifestPath,
        contentHash: "sha256:" + "x".repeat(64),
        manifestHash,
      });

      expect(result.found).toBe(true);
      expect(result.ok).toBe(false);
      expect(result.reason).toContain("content hash mismatch");
      expect(result.mismatches?.contentHash).toBeDefined();
    });

    it("should detect manifest hash mismatch", () => {
      const plugin = createSafePlugin(tempDir);
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      const manifestHash = computeFileHash(plugin.manifestPath).formatted;

      const lockfile = createLockfile();
      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: plugin.manifest.version,
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash,
        manifestHash,
      });

      const result = verifyPluginAgainstLockfile(lockfile, {
        id: plugin.manifest.id,
        version: plugin.manifest.version,
        source: plugin.manifestPath,
        contentHash,
        manifestHash: "sha256:" + "y".repeat(64),
      });

      expect(result.found).toBe(true);
      expect(result.ok).toBe(false);
      expect(result.reason).toContain("manifest hash mismatch");
    });

    it("should report version mismatch as warning", () => {
      const plugin = createSafePlugin(tempDir);
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      const manifestHash = computeFileHash(plugin.manifestPath).formatted;

      const lockfile = createLockfile();
      pinPlugin(lockfile, {
        id: plugin.manifest.id,
        version: "1.0.0",
        source: plugin.manifestPath,
        origin: "workspace",
        contentHash,
        manifestHash,
      });

      const result = verifyPluginAgainstLockfile(lockfile, {
        id: plugin.manifest.id,
        version: "2.0.0", // Different version
        source: plugin.manifestPath,
        contentHash,
        manifestHash,
      });

      // Version mismatch is a warning, not a failure
      expect(result.ok).toBe(true);
      expect(result.mismatches?.version).toBeDefined();
    });

    it("should handle plugin not in lockfile", () => {
      const lockfile = createLockfile();

      const result = verifyPluginAgainstLockfile(lockfile, {
        id: "unknown-plugin",
        source: "/path/to/manifest",
        contentHash: "sha256:" + "a".repeat(64),
        manifestHash: "sha256:" + "a".repeat(64),
      });

      expect(result.found).toBe(false);
      expect(result.ok).toBe(false);
    });
  });

  describe("secret key management", () => {
    it("should create new secret if not exists", () => {
      const secretPath = path.join(tempDir, "secrets", "lockfile.key");

      const secret = loadOrCreateSecret(secretPath);

      expect(secret).toBeTruthy();
      expect(secret.length).toBe(64); // 32 bytes hex
      expect(fs.existsSync(secretPath)).toBe(true);
    });

    it("should load existing secret", () => {
      const secretPath = path.join(tempDir, "secrets", "lockfile.key");
      const existingSecret = "my-existing-secret-key";

      fs.mkdirSync(path.dirname(secretPath), { recursive: true });
      fs.writeFileSync(secretPath, existingSecret);

      const secret = loadOrCreateSecret(secretPath);

      expect(secret).toBe(existingSecret);
    });

    it("should trim whitespace from loaded secret", () => {
      const secretPath = path.join(tempDir, "secrets", "lockfile.key");
      const existingSecret = "  my-secret-with-whitespace  \n";

      fs.mkdirSync(path.dirname(secretPath), { recursive: true });
      fs.writeFileSync(secretPath, existingSecret);

      const secret = loadOrCreateSecret(secretPath);

      expect(secret).toBe("my-secret-with-whitespace");
    });
  });

  describe("lockfile queries", () => {
    it("should list pinned plugin IDs", () => {
      const lockfile = createLockfile();

      pinPlugin(lockfile, {
        id: "plugin-a",
        version: "1.0.0",
        source: "/a",
        origin: "workspace",
        contentHash: "sha256:" + "a".repeat(64),
        manifestHash: "sha256:" + "a".repeat(64),
      });

      pinPlugin(lockfile, {
        id: "plugin-b",
        version: "1.0.0",
        source: "/b",
        origin: "workspace",
        contentHash: "sha256:" + "b".repeat(64),
        manifestHash: "sha256:" + "b".repeat(64),
      });

      const ids = getPinnedPluginIds(lockfile);
      expect(ids).toEqual(["plugin-a", "plugin-b"]);
    });

    it("should get locked plugin by ID", () => {
      const lockfile = createLockfile();

      pinPlugin(lockfile, {
        id: "my-plugin",
        version: "2.0.0",
        source: "/path",
        origin: "global",
        contentHash: "sha256:" + "c".repeat(64),
        manifestHash: "sha256:" + "c".repeat(64),
      });

      const locked = getLockedPlugin(lockfile, "my-plugin");
      expect(locked?.version).toBe("2.0.0");
      expect(locked?.origin).toBe("global");
    });

    it("should check if plugin is pinned", () => {
      const lockfile = createLockfile();

      pinPlugin(lockfile, {
        id: "pinned-plugin",
        version: "1.0.0",
        source: "/path",
        origin: "workspace",
        contentHash: "sha256:" + "d".repeat(64),
        manifestHash: "sha256:" + "d".repeat(64),
      });

      expect(isPluginPinned(lockfile, "pinned-plugin")).toBe(true);
      expect(isPluginPinned(lockfile, "not-pinned")).toBe(false);
    });

    it("should find stale plugins", () => {
      const lockfile = createLockfile();

      // Pin a plugin with old verification date
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 100); // 100 days ago

      lockfile.plugins["old-plugin"] = {
        version: "1.0.0",
        source: "/old",
        origin: "workspace",
        contentHash: "sha256:" + "e".repeat(64),
        manifestHash: "sha256:" + "e".repeat(64),
        signatureVerified: false,
        pinnedAt: oldDate.toISOString(),
        lastVerified: oldDate.toISOString(),
      };

      // Pin a recent plugin
      pinPlugin(lockfile, {
        id: "new-plugin",
        version: "1.0.0",
        source: "/new",
        origin: "workspace",
        contentHash: "sha256:" + "f".repeat(64),
        manifestHash: "sha256:" + "f".repeat(64),
      });

      const stale = getStalePlugins(lockfile, 30); // 30 days threshold
      expect(stale).toContain("old-plugin");
      expect(stale).not.toContain("new-plugin");
    });

    it("should find plugins with security findings", () => {
      const lockfile = createLockfile();

      lockfile.plugins["clean-plugin"] = {
        version: "1.0.0",
        source: "/clean",
        origin: "workspace",
        contentHash: "sha256:" + "a".repeat(64),
        manifestHash: "sha256:" + "a".repeat(64),
        signatureVerified: false,
        pinnedAt: new Date().toISOString(),
        lastVerified: new Date().toISOString(),
        scanFindings: 0,
        scanHighest: "none",
      };

      lockfile.plugins["risky-plugin"] = {
        version: "1.0.0",
        source: "/risky",
        origin: "workspace",
        contentHash: "sha256:" + "b".repeat(64),
        manifestHash: "sha256:" + "b".repeat(64),
        signatureVerified: false,
        pinnedAt: new Date().toISOString(),
        lastVerified: new Date().toISOString(),
        scanFindings: 3,
        scanHighest: "high",
      };

      const withFindings = getPluginsWithFindings(lockfile);
      expect(withFindings).toHaveLength(1);
      expect(withFindings[0].id).toBe("risky-plugin");
      expect(withFindings[0].findings).toBe(3);
      expect(withFindings[0].highest).toBe("high");
    });

    it("should update last verified timestamp", () => {
      const lockfile = createLockfile();

      const oldDate = new Date("2023-01-01").toISOString();
      lockfile.plugins["my-plugin"] = {
        version: "1.0.0",
        source: "/path",
        origin: "workspace",
        contentHash: "sha256:" + "a".repeat(64),
        manifestHash: "sha256:" + "a".repeat(64),
        signatureVerified: false,
        pinnedAt: oldDate,
        lastVerified: oldDate,
      };

      const result = updateLastVerified(lockfile, "my-plugin");
      expect(result).toBe(true);

      const newDate = new Date(lockfile.plugins["my-plugin"].lastVerified);
      expect(newDate.getTime()).toBeGreaterThan(new Date(oldDate).getTime());
    });
  });

  describe("integration with verify flow", () => {
    it("should pass verification when lockfile matches", () => {
      const plugin = createSafePlugin(tempDir);
      const { lockfile, secret } = createTestLockfile(tempDir, [{ plugin }]);

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { lockfile });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.checks.lockfile.status).toBe("pass");
    });

    it("should fail verification when content changed", () => {
      // Use unsigned plugin (no content hash in manifest) so hash check is skipped
      // This allows us to test lockfile verification in isolation
      const plugin = createUnsignedPlugin(tempDir, "lockfile-content-test");
      const { lockfile } = createTestLockfile(tempDir, [{ plugin }]);

      // Modify the plugin file after pinning
      fs.writeFileSync(plugin.entryPath, "// Modified content");

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { lockfile });

      const result = verifyPluginSecurity(ctx);

      // Lockfile verification should fail due to content hash mismatch
      expect(result.ok).toBe(false);
      expect(result.checks.lockfile.status).toBe("fail");
      expect(result.checks.lockfile.details?.contentHash).toBeDefined();
    });

    it("should warn when plugin not in lockfile", () => {
      const plugin = createSafePlugin(tempDir);
      const emptyLockfile = createLockfile();

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { lockfile: emptyLockfile });

      const result = verifyPluginSecurity(ctx);

      // Should still pass but with warning
      expect(result.ok).toBe(true);
      expect(result.checks.lockfile.status).toBe("warn");
    });
  });

  describe("load and save roundtrip", () => {
    it("should preserve all data through save/load cycle", () => {
      const lockfile = createLockfile();
      const secret = "test-secret";

      pinPlugin(lockfile, {
        id: "test-plugin",
        version: "1.2.3",
        source: "/path/to/plugin",
        origin: "global",
        contentHash: "sha256:" + "abc".repeat(21) + "a",
        manifestHash: "sha256:" + "def".repeat(21) + "d",
        signatureVerified: true,
        signedBy: "trusted-key",
        scanFindings: 2,
        scanHighest: "medium",
      });

      const lockfilePath = path.join(tempDir, "roundtrip.lock");
      saveLockfile(lockfilePath, lockfile, secret);

      const loaded = loadLockfile(lockfilePath)!;

      expect(loaded.version).toBe(2);
      expect(verifyLockfileHmac(loaded, secret)).toBe(true);

      const plugin = loaded.plugins["test-plugin"];
      expect(plugin.version).toBe("1.2.3");
      expect(plugin.source).toBe("/path/to/plugin");
      expect(plugin.origin).toBe("global");
      expect(plugin.signatureVerified).toBe(true);
      expect(plugin.signedBy).toBe("trusted-key");
      expect(plugin.scanFindings).toBe(2);
      expect(plugin.scanHighest).toBe("medium");
    });

    it("should return null for non-existent lockfile", () => {
      const result = loadLockfile("/non/existent/path.lock");
      expect(result).toBeNull();
    });

    it("should return null for invalid lockfile version", () => {
      const lockfilePath = path.join(tempDir, "old-version.lock");
      fs.writeFileSync(
        lockfilePath,
        JSON.stringify({ version: 1, plugins: {} }),
      );

      const result = loadLockfile(lockfilePath);
      expect(result).toBeNull();
    });

    it("should return null for malformed JSON", () => {
      const lockfilePath = path.join(tempDir, "malformed.lock");
      fs.writeFileSync(lockfilePath, "{ not valid json");

      const result = loadLockfile(lockfilePath);
      expect(result).toBeNull();
    });
  });
});
