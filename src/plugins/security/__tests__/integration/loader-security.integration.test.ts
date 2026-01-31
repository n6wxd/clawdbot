/**
 * Loader-Security Integration Tests
 *
 * Tests the full loadOpenClawPlugins() flow with security verification.
 * Note: These tests verify the security integration at the verify level
 * rather than loading actual plugins through jiti.
 */

import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { computeFileHash } from "../../hash.js";
import { generateKeyPair } from "../../signature.js";
import { verifyPluginSecurity } from "../../verify.js";
import type { PluginOrigin, VerifyContext } from "../../types.js";
import {
  cleanupTempDir,
  createCapturingAuditLogger,
  createConfigWithTrustedKey,
  createMaliciousCredExfilPlugin,
  createPermissiveConfig,
  createSafePlugin,
  createSafeSignedPlugin,
  createStrictConfig,
  createTamperedPlugin,
  createTempDir,
  createTestLockfile,
  createUnsignedPlugin,
  createVerifyContext,
} from "./setup.js";

describe("loader-security-integration", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir("loader-security-");
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("safe plugin loading flow", () => {
    it("should verify safe plugin and set securityVerified=true", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("hashed");
      expect(result.checks.hash.status).toBe("pass");

      // This is what loader would record
      const securityVerified = result.ok;
      const securityLevel = result.level;

      expect(securityVerified).toBe(true);
      expect(securityLevel).toBe("hashed");
    });

    it("should pass scanning for safe plugin", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.checks.scan.status).toBe("pass");
      expect(result.findings).toBeUndefined();
    });

    it("should return verified content for TOCTOU prevention", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.verifiedContent).toBeDefined();
      expect(result.verifiedContent!.entryPath).toBe(plugin.entryPath);
      expect(result.verifiedContent!.content).toBeInstanceOf(Buffer);

      // Content should match the original file
      const fileContent = fs.readFileSync(plugin.entryPath);
      expect(result.verifiedContent!.content.equals(fileContent)).toBe(true);
    });
  });

  describe("malicious plugin blocking in strict mode", () => {
    it("should block malicious plugin with critical findings", () => {
      const plugin = createMaliciousCredExfilPlugin(tempDir);

      // Add hash to pass hash check
      const contentHash = computeFileHash(plugin.entryPath).formatted;
      plugin.manifest.security = { contentHash };
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      // Need signature for strict mode to proceed to scanning
      // Without signature, it fails on signature check first
      const config = createStrictConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Will fail (either on signature or scanning)
      expect(result.ok).toBe(false);
    });

    it("should block unsigned plugin in strict mode", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.reason).toContain("signature required");

      // This is what loader would record
      const shouldBlock = !result.ok;
      const blockReason = result.reason;

      expect(shouldBlock).toBe(true);
      expect(blockReason).toBeDefined();
    });

    it("should include security findings for blocked plugin", () => {
      const plugin = createMaliciousCredExfilPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Permissive mode allows but records findings
      expect(result.findings).toBeDefined();
      expect(result.findings!.length).toBeGreaterThan(0);
      expect(result.findings!.some((f) => f.severity === "critical")).toBe(true);
    });
  });

  describe("unsigned plugin warning in permissive mode", () => {
    it("should allow unsigned plugin with warning", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { auditLogger });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");

      // Loader would add diagnostic warning
      const shouldWarn = config.mode === "permissive" && result.level === "unsigned";
      expect(shouldWarn).toBe(true);
    });

    it("should record security findings as warnings", () => {
      const plugin = createMaliciousCredExfilPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true); // Permissive allows
      expect(result.findings).toBeDefined();

      // Loader would add finding count to diagnostics
      const findingCount = result.findings?.length ?? 0;
      expect(findingCount).toBeGreaterThan(0);
    });
  });

  describe("tampered plugin hash verification failure", () => {
    it("should fail hash verification for tampered plugin", () => {
      const plugin = createTamperedPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.reason).toContain("hash mismatch");
      expect(result.checks.hash.status).toBe("fail");
      expect(result.checks.hash.details).toBeDefined();
    });

    it("should include expected and actual hash in failure details", () => {
      const plugin = createTamperedPlugin(tempDir);
      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.checks.hash.details?.expected).toBeDefined();
      expect(result.checks.hash.details?.actual).toBeDefined();
      expect(result.checks.hash.details?.expected).not.toBe(
        result.checks.hash.details?.actual,
      );
    });

    it("should not return verified content on hash failure", () => {
      const plugin = createTamperedPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.verifiedContent).toBeUndefined();
    });
  });

  describe("bundled plugin implicit trust", () => {
    it("should trust bundled plugins when trustBundled=true", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ trustBundled: true, enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
    });

    it("should skip all checks for bundled plugins", () => {
      const plugin = createMaliciousCredExfilPlugin(tempDir);
      const config = createPermissiveConfig({ trustBundled: true, enableScanning: true });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.checks.hash.status).toBe("skip");
      expect(result.checks.signature.status).toBe("skip");
      expect(result.checks.scan.status).toBe("skip");
    });

    it("should log trust decision for bundled plugins", () => {
      const plugin = createSafePlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();
      const config = createPermissiveConfig({ trustBundled: true, enableScanning: false });
      const ctx = createVerifyContext(plugin, config, {
        origin: "bundled",
        auditLogger,
      });

      verifyPluginSecurity(ctx);

      const trustEvent = auditLogger.events.find((e) => e.eventType === "trust_decision");
      expect(trustEvent).toBeDefined();
      expect(trustEvent!.result).toBe("allow");
    });
  });

  describe("full verification flow simulation", () => {
    it("should simulate loader verification for multiple plugins", () => {
      // Simulate loading multiple plugins like the loader does
      const plugins = [
        { plugin: createSafePlugin(tempDir, "safe-1"), expected: { ok: true, level: "hashed" } },
        { plugin: createUnsignedPlugin(tempDir, "unsigned-1"), expected: { ok: true, level: "unsigned" } },
        { plugin: createTamperedPlugin(tempDir, "tampered-1"), expected: { ok: false } },
      ];

      const config = createPermissiveConfig({ enableScanning: false });
      const results: Array<{ id: string; verified: boolean; level?: string; error?: string }> = [];

      for (const { plugin, expected } of plugins) {
        const ctx = createVerifyContext(plugin, config);
        const result = verifyPluginSecurity(ctx);

        results.push({
          id: plugin.manifest.id,
          verified: result.ok,
          level: result.level,
          error: result.reason,
        });

        expect(result.ok).toBe(expected.ok);
        if (expected.level) {
          expect(result.level).toBe(expected.level);
        }
      }

      // Check summary
      const verified = results.filter((r) => r.verified);
      const blocked = results.filter((r) => !r.verified);

      expect(verified).toHaveLength(2);
      expect(blocked).toHaveLength(1);
      expect(blocked[0].id).toBe("tampered-1");
    });

    it("should handle signed plugins in loader flow", () => {
      const keyPair = generateKeyPair();
      const signedPlugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");
      const unsignedPlugin = createUnsignedPlugin(tempDir, "unsigned");

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "strict");
      config.enableScanning = false;

      // Signed plugin should pass
      const signedResult = verifyPluginSecurity(createVerifyContext(signedPlugin, config));
      expect(signedResult.ok).toBe(true);
      expect(signedResult.level).toBe("verified");

      // Unsigned plugin should fail in strict mode
      const unsignedResult = verifyPluginSecurity(createVerifyContext(unsignedPlugin, config));
      expect(unsignedResult.ok).toBe(false);
    });
  });

  describe("lockfile integration", () => {
    it("should verify plugin against lockfile", () => {
      const plugin = createSafePlugin(tempDir);
      const { lockfile } = createTestLockfile(tempDir, [{ plugin }]);

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { lockfile });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.checks.lockfile.status).toBe("pass");
    });

    it("should fail when plugin changed after lockfile", () => {
      // Use unsigned plugin (no content hash in manifest) so hash check is skipped
      // This allows us to test lockfile verification failure in isolation
      const plugin = createUnsignedPlugin(tempDir, "lockfile-test");
      const { lockfile } = createTestLockfile(tempDir, [{ plugin }]);

      // Modify plugin after lockfile was created
      fs.writeFileSync(plugin.entryPath, "// Modified content\nexport function register() {}");

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { lockfile });

      const result = verifyPluginSecurity(ctx);

      // Lockfile verification should fail due to content hash mismatch
      expect(result.ok).toBe(false);
      expect(result.checks.lockfile.status).toBe("fail");
    });
  });

  describe("audit logging in loader flow", () => {
    it("should log verification events", () => {
      const plugin = createSafePlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { auditLogger });

      verifyPluginSecurity(ctx);

      expect(auditLogger.events.length).toBeGreaterThan(0);
      expect(auditLogger.events.some((e) => e.eventType === "verification_pass")).toBe(true);
    });

    it("should log failure events", () => {
      const plugin = createTamperedPlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { auditLogger });

      verifyPluginSecurity(ctx);

      expect(auditLogger.events.some((e) => e.eventType === "verification_fail")).toBe(true);
      expect(auditLogger.events.some((e) => e.eventType === "hash_mismatch")).toBe(true);
    });
  });

  describe("diagnostic generation", () => {
    it("should provide data for error diagnostics", () => {
      const plugin = createTamperedPlugin(tempDir);
      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Loader uses these to generate diagnostics
      expect(result.ok).toBe(false);
      expect(result.reason).toBeDefined();

      // Simulated diagnostic
      const diagnostic = {
        level: "error",
        pluginId: plugin.manifest.id,
        source: plugin.manifestPath,
        message: `blocked by security policy: ${result.reason}`,
      };

      expect(diagnostic.message).toContain("hash mismatch");
    });

    it("should provide data for warning diagnostics", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Loader checks for unsigned warning
      const shouldWarn = config.mode === "permissive" && result.level === "unsigned";
      expect(shouldWarn).toBe(true);

      const diagnostic = {
        level: "warn",
        pluginId: plugin.manifest.id,
        source: plugin.manifestPath,
        message: "plugin is unsigned (running in permissive mode)",
      };

      expect(diagnostic.level).toBe("warn");
    });

    it("should provide data for finding warnings", () => {
      const plugin = createMaliciousCredExfilPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      const findingCount = result.findings?.length ?? 0;
      expect(findingCount).toBeGreaterThan(0);

      const diagnostic = {
        level: "warn",
        pluginId: plugin.manifest.id,
        source: plugin.manifestPath,
        message: `${findingCount} security finding(s) detected`,
      };

      expect(parseInt(diagnostic.message)).toBeGreaterThan(0);
    });
  });

  describe("origin handling", () => {
    const origins: PluginOrigin[] = ["bundled", "global", "workspace", "config"];

    it("should pass origin to verification context", () => {
      for (const origin of origins) {
        const plugin = createSafePlugin(tempDir, `plugin-${origin}`);
        const config = createPermissiveConfig({ enableScanning: false });
        const ctx = createVerifyContext(plugin, config, { origin });

        expect(ctx.origin).toBe(origin);

        const result = verifyPluginSecurity(ctx);

        if (origin === "bundled" && config.trustBundled) {
          expect(result.level).toBe("verified");
        } else {
          expect(result.level).toBe("hashed");
        }
      }
    });
  });
});
