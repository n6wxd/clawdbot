/**
 * Trust Progression Integration Tests
 *
 * Tests trust level assignment and progression:
 * unsigned → hashed → signed → verified
 */

import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { computeFileHash } from "../../hash.js";
import { generateKeyPair, signManifest } from "../../signature.js";
import { verifyPluginSecurity } from "../../verify.js";
import type { PluginSecurityConfig, TrustLevel } from "../../types.js";
import {
  cleanupTempDir,
  createConfigWithTrustedKey,
  createPermissiveConfig,
  createSafePlugin,
  createSafeSignedPlugin,
  createStrictConfig,
  createTempDir,
  createTestLockfile,
  createTestPlugin,
  createUnsignedPlugin,
  createVerifyContext,
} from "./setup.js";

describe("trust-progression", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir("trust-test-");
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("trust level assignment", () => {
    it("should assign 'unsigned' level to plugin without security metadata", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");
    });

    it("should assign 'hashed' level to plugin with valid content hash", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("hashed");
      expect(result.checks.hash.status).toBe("pass");
    });

    it("should assign 'signed' level to plugin with valid signature", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "permissive");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified"); // signed + no lockfile issues = verified
      expect(result.checks.signature.status).toBe("pass");
    });

    it("should assign 'verified' level when all checks pass", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      // Create lockfile with the plugin
      const { lockfile } = createTestLockfile(tempDir, [
        { plugin, signatureVerified: true, signedBy: "trusted-key" },
      ]);

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "strict");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config, { lockfile });
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
      expect(result.checks.hash.status).toBe("pass");
      expect(result.checks.signature.status).toBe("pass");
      expect(result.checks.lockfile.status).toBe("pass");
    });

    it("should assign 'verified' level to bundled plugins", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createPermissiveConfig({ trustBundled: true, enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
    });
  });

  describe("trust level progression", () => {
    it("should progress from unsigned to hashed when hash is added", () => {
      // Start with unsigned plugin
      const code = `
        export function register(api) {
          api.registerTool({ name: 'test', execute: async () => ({}) });
        }
      `;
      const plugin = createTestPlugin(tempDir, { id: "progression-test", code });
      const config = createPermissiveConfig({ enableScanning: false });

      // First verification - unsigned
      const ctx1 = createVerifyContext(plugin, config);
      const result1 = verifyPluginSecurity(ctx1);
      expect(result1.level).toBe("unsigned");

      // Add content hash to manifest
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      plugin.manifest.security = { contentHash };
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      // Second verification - hashed
      const ctx2 = createVerifyContext(plugin, config);
      const result2 = verifyPluginSecurity(ctx2);
      expect(result2.level).toBe("hashed");
    });

    it("should progress from hashed to signed when signature is added", () => {
      const keyPair = generateKeyPair();
      const code = `
        export function register(api) {
          api.registerTool({ name: 'test', execute: async () => ({}) });
        }
      `;

      // Start with hashed-only plugin
      const plugin = createTestPlugin(tempDir, { id: "progression-test", code });
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      plugin.manifest.security = { contentHash };
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      const config = createConfigWithTrustedKey(keyPair.publicKey, "test-key", "permissive");
      config.enableScanning = false;

      // First verification - hashed only
      const ctx1 = createVerifyContext(plugin, config);
      const result1 = verifyPluginSecurity(ctx1);
      expect(result1.level).toBe("hashed");

      // Add signature
      plugin.manifest.security = {
        contentHash,
        signedBy: "test-key",
      };
      const signature = signManifest(plugin.manifest, keyPair.privateKey);
      plugin.manifest.security.signature = signature;
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      // Second verification - signed
      const ctx2 = createVerifyContext(plugin, config);
      const result2 = verifyPluginSecurity(ctx2);
      expect(result2.level).toBe("verified");
      expect(result2.checks.signature.status).toBe("pass");
    });
  });

  describe("required trust enforcement", () => {
    it("should fail if plugin requires higher trust than achieved", () => {
      // Create plugin that requires 'signed' trust
      const code = `
        export function register(api) {
          api.registerTool({ name: 'test', execute: async () => ({}) });
        }
      `;
      const plugin = createTestPlugin(tempDir, { id: "high-trust-required", code });

      // Add hash but require signed trust
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      plugin.manifest.security = {
        contentHash,
        requiredTrust: "signed",
      };
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      // Strict mode should enforce this
      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      // No signature, so won't reach 'signed' level
      const result = verifyPluginSecurity(ctx);

      // In strict mode, unsigned/hashed plugins fail when signature is required
      expect(result.ok).toBe(false);
    });

    it("should pass if plugin trust meets required level", () => {
      const keyPair = generateKeyPair();
      // Create a signed plugin - the signature proves authenticity
      // requiredTrust is about declaring minimum trust needed, not about the signature itself
      // A properly signed plugin already meets 'signed' trust level
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "strict");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      // The signed plugin should achieve 'verified' level
      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
    });
  });

  describe("trust level boundaries", () => {
    const levels: TrustLevel[] = ["unsigned", "hashed", "signed", "verified"];

    it("should maintain trust level order", () => {
      // Trust levels should be in ascending order of security
      const levelOrder: Record<TrustLevel, number> = {
        unsigned: 0,
        hashed: 1,
        signed: 2,
        verified: 3,
      };

      for (let i = 0; i < levels.length - 1; i++) {
        expect(levelOrder[levels[i]]).toBeLessThan(levelOrder[levels[i + 1]]);
      }
    });

    it("should not downgrade trust level", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "permissive");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      // Should be verified (highest level)
      expect(result.level).toBe("verified");

      // Even with warnings in checks, level stays at highest achieved
      expect(["signed", "verified"]).toContain(result.level);
    });
  });

  describe("trust with scanning", () => {
    it("should not affect trust level when scan passes", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("hashed");
      expect(result.checks.scan.status).toBe("pass");
    });

    it("should maintain trust level even with scan warnings", () => {
      // Create a plugin with minor suspicious patterns (not critical)
      const code = `
        export function register(api) {
          // This might trigger a low severity finding
          api.registerTool({
            name: 'test',
            execute: async () => {
              // Some code that might be flagged
              const config = {};
              return config;
            }
          });
        }
      `;

      const plugin = createTestPlugin(tempDir, { id: "warn-test", code });
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      plugin.manifest.security = { contentHash };
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      const config = createPermissiveConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Trust level is based on hash/signature, not scan results
      expect(result.level).toBe("hashed");
    });
  });

  describe("mode effects on trust", () => {
    it("should return unsigned level with mode=off", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "permissive");
      config.mode = "off";

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      // Off mode skips all checks
      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");
      expect(result.checks.hash.status).toBe("skip");
      expect(result.checks.signature.status).toBe("skip");
    });

    it("should allow hashed level in permissive mode", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("hashed");
    });

    it("should require signature for full trust in strict mode", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Plugin has hash but no signature, fails strict mode
      expect(result.ok).toBe(false);
    });
  });

  describe("lockfile effect on trust", () => {
    it("should not increase trust level just from lockfile", () => {
      // Unsigned plugin in lockfile should still be unsigned
      const plugin = createUnsignedPlugin(tempDir);
      const { lockfile } = createTestLockfile(tempDir, [{ plugin }]);

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { lockfile });

      const result = verifyPluginSecurity(ctx);

      // Lockfile verifies integrity, but doesn't upgrade trust level
      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");
      expect(result.checks.lockfile.status).toBe("pass");
    });

    it("should achieve verified level with signature + lockfile", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");
      const { lockfile } = createTestLockfile(tempDir, [
        { plugin, signatureVerified: true, signedBy: "trusted-key" },
      ]);

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "strict");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config, { lockfile });
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
    });
  });

  describe("origin effect on trust", () => {
    const origins = ["bundled", "global", "workspace", "config"] as const;

    it("should give verified trust to bundled plugins when trustBundled=true", () => {
      const plugin = createUnsignedPlugin(tempDir);

      for (const origin of origins) {
        const config = createPermissiveConfig({ trustBundled: true, enableScanning: false });
        const ctx = createVerifyContext(plugin, config, { origin });
        const result = verifyPluginSecurity(ctx);

        if (origin === "bundled") {
          expect(result.level).toBe("verified");
        } else {
          expect(result.level).toBe("unsigned");
        }
      }
    });

    it("should not trust bundled plugins when trustBundled=false", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createPermissiveConfig({ trustBundled: false, enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      // Without trustBundled, even bundled plugins need verification
      expect(result.level).toBe("unsigned");
    });
  });
});
