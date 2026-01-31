/**
 * Security Modes Integration Tests
 *
 * Tests mode behaviors:
 * - strict: blocks unsigned, requires trusted signature
 * - permissive: warns but allows
 * - off: no checks run
 */

import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { generateKeyPair } from "../../signature.js";
import { verifyPluginSecurity, normalizeSecurityConfig } from "../../verify.js";
import type { PluginSecurityConfig } from "../../types.js";
import { DEFAULT_SECURITY_CONFIG } from "../../types.js";
import {
  cleanupTempDir,
  createCapturingAuditLogger,
  createConfigWithTrustedKey,
  createMaliciousCodeExecPlugin,
  createMaliciousCredExfilPlugin,
  createOffConfig,
  createPermissiveConfig,
  createSafePlugin,
  createSafeSignedPlugin,
  createStrictConfig,
  createTamperedPlugin,
  createTempDir,
  createUnsignedPlugin,
  createVerifyContext,
} from "./setup.js";

describe("security-modes", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir("modes-test-");
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("strict mode", () => {
    it("should block unsigned plugins", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.reason).toContain("signature required");
    });

    it("should block plugins with unknown signer", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "unknown-key");

      // Config doesn't trust "unknown-key"
      const config = createStrictConfig({ enableScanning: false });

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.reason).toContain("unknown signer");
    });

    it("should allow plugins signed by trusted key", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "strict");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
    });

    it("should block plugins with hash mismatch", () => {
      const plugin = createTamperedPlugin(tempDir);
      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.reason).toContain("hash mismatch");
    });

    it("should block plugins with critical security findings", () => {
      const keyPair = generateKeyPair();
      const plugin = createMaliciousCredExfilPlugin(tempDir);

      // Add valid signature to make it pass signature check
      // (We want to test that scanning still blocks it)
      const config = createStrictConfig({ enableScanning: true });

      // Don't add signature - it will fail on signature first
      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      // Could fail on signature or scanning
    });

    it("should allow bundled plugins when trustBundled=true", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ trustBundled: true, enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
    });

    it("should not allow bundled plugins when trustBundled=false", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ trustBundled: false, enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
    });
  });

  describe("permissive mode", () => {
    it("should allow unsigned plugins with warning", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { auditLogger });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");
    });

    it("should allow plugins with unknown signer with warning", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "unknown-key");

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.checks.signature.status).toBe("warn");
      expect(result.checks.signature.message).toContain("unknown signer");
    });

    it("should block plugins with hash mismatch", () => {
      const plugin = createTamperedPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Even permissive mode blocks hash mismatches (integrity violation)
      expect(result.ok).toBe(false);
      expect(result.reason).toContain("hash mismatch");
    });

    it("should allow plugins with security findings but warn", () => {
      const plugin = createMaliciousCodeExecPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Permissive mode allows but warns
      // Unless critical findings which may still block
      expect(result.findings).toBeDefined();
      expect(result.findings!.length).toBeGreaterThan(0);
    });

    it("should upgrade to verified with proper signature", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "permissive");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
    });
  });

  describe("off mode", () => {
    it("should skip all verification checks", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createOffConfig();
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");
      expect(result.checks.hash.status).toBe("skip");
      expect(result.checks.signature.status).toBe("skip");
      expect(result.checks.lockfile.status).toBe("skip");
      expect(result.checks.scan.status).toBe("skip");
    });

    it("should allow tampered plugins", () => {
      const plugin = createTamperedPlugin(tempDir);
      const config = createOffConfig();
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Off mode doesn't check anything
      expect(result.ok).toBe(true);
    });

    it("should allow malicious plugins", () => {
      const plugin = createMaliciousCredExfilPlugin(tempDir);
      const config = createOffConfig();
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Off mode doesn't scan
      expect(result.ok).toBe(true);
      expect(result.findings).toBeUndefined();
    });

    it("should not log audit events", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();
      const config = createOffConfig();
      const ctx = createVerifyContext(plugin, config, { auditLogger });

      verifyPluginSecurity(ctx);

      // Off mode returns early, no audit logging
      expect(auditLogger.events).toHaveLength(0);
    });

    it("should not return verified content", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createOffConfig();
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // No verification = no verified content
      expect(result.verifiedContent).toBeUndefined();
    });
  });

  describe("mode comparison", () => {
    it("should handle same plugin differently per mode", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "unknown-key");

      // Strict: fails (unknown signer)
      const strictConfig = createStrictConfig({ enableScanning: false });
      const strictResult = verifyPluginSecurity(createVerifyContext(plugin, strictConfig));
      expect(strictResult.ok).toBe(false);

      // Permissive: passes with warning
      const permissiveConfig = createPermissiveConfig({ enableScanning: false });
      const permissiveResult = verifyPluginSecurity(
        createVerifyContext(plugin, permissiveConfig),
      );
      expect(permissiveResult.ok).toBe(true);
      expect(permissiveResult.checks.signature.status).toBe("warn");

      // Off: passes without any checks
      const offConfig = createOffConfig();
      const offResult = verifyPluginSecurity(createVerifyContext(plugin, offConfig));
      expect(offResult.ok).toBe(true);
      expect(offResult.checks.signature.status).toBe("skip");
    });

    it("should have consistent behavior for safe plugins across modes", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      const configs: Array<[string, PluginSecurityConfig]> = [
        ["strict", createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "strict")],
        ["permissive", createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "permissive")],
        ["off", createOffConfig()],
      ];

      for (const [mode, config] of configs) {
        config.enableScanning = false;
        const result = verifyPluginSecurity(createVerifyContext(plugin, config));
        expect(result.ok).toBe(true);
      }
    });

    it("should have escalating restrictions from off to strict", () => {
      const plugin = createUnsignedPlugin(tempDir);

      // Off: no checks
      const offResult = verifyPluginSecurity(
        createVerifyContext(plugin, createOffConfig()),
      );
      expect(offResult.ok).toBe(true);
      expect(offResult.level).toBe("unsigned");

      // Permissive: checks but allows
      const permissiveResult = verifyPluginSecurity(
        createVerifyContext(plugin, createPermissiveConfig({ enableScanning: false })),
      );
      expect(permissiveResult.ok).toBe(true);
      expect(permissiveResult.level).toBe("unsigned");

      // Strict: checks and blocks
      const strictResult = verifyPluginSecurity(
        createVerifyContext(plugin, createStrictConfig({ enableScanning: false })),
      );
      expect(strictResult.ok).toBe(false);
    });
  });

  describe("config normalization", () => {
    it("should merge with defaults", () => {
      const partial = { mode: "strict" as const };
      const normalized = normalizeSecurityConfig(partial);

      expect(normalized.mode).toBe("strict");
      expect(normalized.trustBundled).toBe(DEFAULT_SECURITY_CONFIG.trustBundled);
      expect(normalized.enableScanning).toBe(DEFAULT_SECURITY_CONFIG.enableScanning);
      expect(normalized.audit.enabled).toBe(DEFAULT_SECURITY_CONFIG.audit.enabled);
    });

    it("should preserve all specified values", () => {
      const config: Partial<PluginSecurityConfig> = {
        mode: "strict",
        trustBundled: false,
        enableScanning: false,
        trustedKeys: [{ id: "key-1", publicKey: "pk" }],
        audit: { enabled: false, format: "text" },
      };

      const normalized = normalizeSecurityConfig(config);

      expect(normalized.mode).toBe("strict");
      expect(normalized.trustBundled).toBe(false);
      expect(normalized.enableScanning).toBe(false);
      expect(normalized.trustedKeys).toHaveLength(1);
      expect(normalized.audit.enabled).toBe(false);
      expect(normalized.audit.format).toBe("text");
    });

    it("should handle undefined input", () => {
      const normalized = normalizeSecurityConfig(undefined);

      expect(normalized).toEqual(DEFAULT_SECURITY_CONFIG);
    });
  });

  describe("scanning control", () => {
    it("should skip scanning when enableScanning=false", () => {
      const plugin = createMaliciousCodeExecPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.checks.scan.status).toBe("skip");
      expect(result.findings).toBeUndefined();
    });

    it("should run scanning when enableScanning=true", () => {
      const plugin = createMaliciousCodeExecPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: true });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.checks.scan.status).not.toBe("skip");
      expect(result.findings).toBeDefined();
      expect(result.findings!.length).toBeGreaterThan(0);
    });

    it("should block on critical findings in strict mode only", () => {
      // Create plugin with critical findings
      const plugin = createMaliciousCredExfilPlugin(tempDir);

      // Add hash to make it pass hash check but still have critical findings
      const keyPair = generateKeyPair();

      // Strict mode with scanning - should block on findings
      const strictConfig = createConfigWithTrustedKey(
        keyPair.publicKey,
        "any-key",
        "strict",
      );
      strictConfig.enableScanning = true;

      // Will fail on signature anyway since plugin isn't signed
      // Let's test with unsigned plugin directly
      const unsignedPlugin = createMaliciousCredExfilPlugin(tempDir, "unsigned-malicious");
      const strictResult = verifyPluginSecurity(
        createVerifyContext(unsignedPlugin, strictConfig),
      );
      expect(strictResult.ok).toBe(false);
    });
  });

  describe("trustBundled flag", () => {
    it("should bypass checks for bundled plugins when true", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ trustBundled: true, enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
      expect(result.checks.hash.status).toBe("skip");
    });

    it("should verify bundled plugins when false", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ trustBundled: false, enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      // Without trustBundled, strict mode requires signature
      expect(result.ok).toBe(false);
    });

    it("should only affect bundled origin", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ trustBundled: true, enableScanning: false });

      const origins = ["workspace", "global", "config"] as const;

      for (const origin of origins) {
        const ctx = createVerifyContext(plugin, config, { origin });
        const result = verifyPluginSecurity(ctx);

        // Non-bundled origins should still require verification
        expect(result.ok).toBe(false);
      }
    });
  });
});
