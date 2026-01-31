/**
 * Signature Real Keys Integration Tests
 *
 * Tests Ed25519 signature operations with real key pairs.
 */

import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { computeFileHash } from "../../hash.js";
import {
  computeKeyFingerprint,
  encodePublicKeyForConfig,
  generateKeyPair,
  hasSignature,
  loadPublicKey,
  loadTrustedKeys,
  saveKeyPair,
  signManifest,
  verifyKeyId,
  verifyManifestSignature,
} from "../../signature.js";
import { verifyPluginSecurity } from "../../verify.js";
import type { PluginSecurityManifest } from "../../types.js";
import {
  cleanupTempDir,
  createConfigWithTrustedKey,
  createPermissiveConfig,
  createSafeSignedPlugin,
  createSignedPlugin,
  createStrictConfig,
  createTempDir,
  createUnsignedPlugin,
  createVerifyContext,
} from "./setup.js";

describe("signature-real-keys", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir("signature-test-");
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("key generation", () => {
    it("should generate valid Ed25519 key pair", () => {
      const { publicKey, privateKey } = generateKeyPair();

      expect(publicKey).toContain("-----BEGIN PUBLIC KEY-----");
      expect(publicKey).toContain("-----END PUBLIC KEY-----");
      expect(privateKey).toContain("-----BEGIN PRIVATE KEY-----");
      expect(privateKey).toContain("-----END PRIVATE KEY-----");
    });

    it("should generate unique key pairs each time", () => {
      const pair1 = generateKeyPair();
      const pair2 = generateKeyPair();

      expect(pair1.publicKey).not.toBe(pair2.publicKey);
      expect(pair1.privateKey).not.toBe(pair2.privateKey);
    });

    it("should save and load key pairs", () => {
      const keyPair = generateKeyPair();
      const keyId = "test-key";

      const { publicKeyPath, privateKeyPath } = saveKeyPair(tempDir, keyId, keyPair);

      expect(fs.existsSync(publicKeyPath)).toBe(true);
      expect(fs.existsSync(privateKeyPath)).toBe(true);

      const loadedPublic = loadPublicKey(publicKeyPath);
      expect(loadedPublic).toBe(keyPair.publicKey);
    });

    it("should set correct file permissions on saved keys", () => {
      const keyPair = generateKeyPair();
      const { publicKeyPath, privateKeyPath } = saveKeyPair(tempDir, "test-key", keyPair);

      const publicStats = fs.statSync(publicKeyPath);
      const privateStats = fs.statSync(privateKeyPath);

      // Public key should be readable (0o644)
      expect((publicStats.mode & 0o777).toString(8)).toBe("644");

      // Private key should be restricted (0o600)
      expect((privateStats.mode & 0o777).toString(8)).toBe("600");
    });
  });

  describe("signing and verification", () => {
    it("should sign and verify a manifest", () => {
      const keyPair = generateKeyPair();

      const manifest = {
        id: "test-plugin",
        version: "1.0.0",
        security: {
          contentHash: "sha256:" + "a".repeat(64),
          signedBy: "test-key",
        } as PluginSecurityManifest,
      };

      // Sign the manifest
      const signature = signManifest(manifest, keyPair.privateKey);
      expect(signature).toBeTruthy();
      expect(signature.length).toBeGreaterThan(0);

      // Add signature to manifest
      manifest.security!.signature = signature;

      // Verify the signature
      const result = verifyManifestSignature(manifest, keyPair.publicKey);
      expect(result.ok).toBe(true);
    });

    it("should reject tampered manifest", () => {
      const keyPair = generateKeyPair();

      const manifest = {
        id: "test-plugin",
        version: "1.0.0",
        security: {
          contentHash: "sha256:" + "a".repeat(64),
          signedBy: "test-key",
        } as PluginSecurityManifest,
      };

      // Sign the manifest
      const signature = signManifest(manifest, keyPair.privateKey);
      manifest.security!.signature = signature;

      // Tamper with the manifest
      manifest.version = "2.0.0";

      // Verification should fail
      const result = verifyManifestSignature(manifest, keyPair.publicKey);
      expect(result.ok).toBe(false);
      expect(result.reason).toContain("failed");
    });

    it("should reject signature from wrong key", () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();

      const manifest = {
        id: "test-plugin",
        version: "1.0.0",
        security: {
          contentHash: "sha256:" + "a".repeat(64),
          signedBy: "test-key",
        } as PluginSecurityManifest,
      };

      // Sign with key 1
      const signature = signManifest(manifest, keyPair1.privateKey);
      manifest.security!.signature = signature;

      // Verify with key 2 - should fail
      const result = verifyManifestSignature(manifest, keyPair2.publicKey);
      expect(result.ok).toBe(false);
    });

    it("should reject manifest without signature", () => {
      const keyPair = generateKeyPair();

      const manifest = {
        id: "test-plugin",
        version: "1.0.0",
        security: {
          contentHash: "sha256:" + "a".repeat(64),
          signedBy: "test-key",
        } as PluginSecurityManifest,
      };

      const result = verifyManifestSignature(manifest, keyPair.publicKey);
      expect(result.ok).toBe(false);
      expect(result.reason).toContain("no signature");
    });
  });

  describe("canonical manifest data", () => {
    it("should produce consistent signatures regardless of property order", () => {
      const keyPair = generateKeyPair();

      // Create two manifests with same data but different property order
      const manifest1 = {
        id: "test-plugin",
        version: "1.0.0",
        security: {
          contentHash: "sha256:" + "a".repeat(64),
          signedBy: "test-key",
        } as PluginSecurityManifest,
      };

      const manifest2 = {
        version: "1.0.0",
        id: "test-plugin",
        security: {
          signedBy: "test-key",
          contentHash: "sha256:" + "a".repeat(64),
        } as PluginSecurityManifest,
      };

      const sig1 = signManifest(manifest1, keyPair.privateKey);
      const sig2 = signManifest(manifest2, keyPair.privateKey);

      // Signatures should be identical
      expect(sig1).toBe(sig2);
    });

    it("should exclude signature field from signing data", () => {
      const keyPair = generateKeyPair();

      const manifest = {
        id: "test-plugin",
        version: "1.0.0",
        security: {
          contentHash: "sha256:" + "a".repeat(64),
          signedBy: "test-key",
        } as PluginSecurityManifest,
      };

      // Sign first time
      const sig1 = signManifest(manifest, keyPair.privateKey);

      // Add signature and sign again
      manifest.security!.signature = sig1;
      const sig2 = signManifest(manifest, keyPair.privateKey);

      // Should be the same (signature field excluded)
      expect(sig1).toBe(sig2);
    });
  });

  describe("trusted key management", () => {
    it("should load trusted keys from config", () => {
      const keyPair = generateKeyPair();
      const encoded = encodePublicKeyForConfig(keyPair.publicKey);

      const trustedKeys = [
        { id: "key-1", publicKey: encoded },
        { id: "key-2", publicKey: keyPair.publicKey }, // PEM format
      ];

      const keyMap = loadTrustedKeys(trustedKeys);

      expect(keyMap.size).toBe(2);
      expect(keyMap.has("key-1")).toBe(true);
      expect(keyMap.has("key-2")).toBe(true);
    });

    it("should skip invalid keys without throwing", () => {
      const trustedKeys = [
        { id: "good-key", publicKey: generateKeyPair().publicKey },
        { id: "bad-key", publicKey: "not-a-valid-key" },
      ];

      const keyMap = loadTrustedKeys(trustedKeys);

      // Should have loaded at least the good key
      expect(keyMap.has("good-key")).toBe(true);
    });

    it("should encode public key for config storage", () => {
      const keyPair = generateKeyPair();
      const encoded = encodePublicKeyForConfig(keyPair.publicKey);

      expect(encoded).toMatch(/^base64:/);
      expect(encoded).not.toContain("-----BEGIN");
      expect(encoded).not.toContain("\n");
    });
  });

  describe("key fingerprinting", () => {
    it("should compute consistent fingerprint", () => {
      const keyPair = generateKeyPair();

      const fp1 = computeKeyFingerprint(keyPair.publicKey);
      const fp2 = computeKeyFingerprint(keyPair.publicKey);

      expect(fp1).toBe(fp2);
    });

    it("should produce different fingerprints for different keys", () => {
      const key1 = generateKeyPair();
      const key2 = generateKeyPair();

      const fp1 = computeKeyFingerprint(key1.publicKey);
      const fp2 = computeKeyFingerprint(key2.publicKey);

      expect(fp1).not.toBe(fp2);
    });

    it("should verify key ID against fingerprint", () => {
      const keyPair = generateKeyPair();
      const fingerprint = computeKeyFingerprint(keyPair.publicKey);

      // Fingerprint format is "abc1:def2:..." - verifyKeyId compares prefix
      // The function strips colons from keyId but keeps them in fingerprint
      // So we need to test with the colon-separated prefix format

      // Get first segment of fingerprint (before first colon group matches)
      const segments = fingerprint.split(":");
      const firstSegment = segments[0];

      // First segment as prefix should match
      expect(verifyKeyId(firstSegment, keyPair.publicKey)).toBe(true);

      // Wrong ID should not match
      expect(verifyKeyId("0000", keyPair.publicKey)).toBe(false);
      expect(verifyKeyId("wrong-id", keyPair.publicKey)).toBe(false);
    });
  });

  describe("integration with verify flow", () => {
    it("should verify signed plugin with trusted key", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "strict");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("verified");
      expect(result.checks.signature.status).toBe("pass");
    });

    it("should warn for unknown signer in permissive mode", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "unknown-key");

      // Config without the signing key
      const config = createPermissiveConfig({ enableScanning: false });

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.checks.signature.status).toBe("warn");
      expect(result.checks.signature.message).toContain("unknown signer");
    });

    it("should block unknown signer in strict mode", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "unknown-key");

      // Strict config without the signing key
      const config = createStrictConfig({ enableScanning: false });

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.reason).toContain("unknown signer");
    });

    it("should block unsigned plugin in strict mode", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createStrictConfig({ enableScanning: false });

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.checks.signature.status).toBe("skip");
    });

    it("should allow unsigned plugin in permissive mode", () => {
      const plugin = createUnsignedPlugin(tempDir);
      const config = createPermissiveConfig({ enableScanning: false });

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.level).toBe("unsigned");
    });

    it("should detect tampered signature", () => {
      const keyPair = generateKeyPair();
      const plugin = createSafeSignedPlugin(tempDir, keyPair, "trusted-key");

      // Tamper with the signature
      const tamperedSig = "A" + plugin.manifest.security!.signature!.slice(1);
      plugin.manifest.security!.signature = tamperedSig;
      fs.writeFileSync(plugin.manifestPath, JSON.stringify(plugin.manifest, null, 2));

      const config = createConfigWithTrustedKey(keyPair.publicKey, "trusted-key", "strict");
      config.enableScanning = false;

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.checks.signature.status).toBe("fail");
    });
  });

  describe("hasSignature utility", () => {
    it("should detect presence of signature", () => {
      const withSig = {
        security: {
          signature: "base64signature",
          signedBy: "key-id",
        },
      };

      const withoutSig = {
        security: {
          contentHash: "sha256:abc",
        },
      };

      const noSecurity = {};

      expect(hasSignature(withSig)).toBe(true);
      expect(hasSignature(withoutSig)).toBe(false);
      expect(hasSignature(noSecurity)).toBe(false);
    });
  });

  describe("multiple trusted keys", () => {
    it("should accept signature from any trusted key", () => {
      const key1 = generateKeyPair();
      const key2 = generateKeyPair();

      // Sign with key 2
      const plugin = createSafeSignedPlugin(tempDir, key2, "key-2");

      // Config trusts both keys
      const config = createStrictConfig({
        enableScanning: false,
        trustedKeys: [
          { id: "key-1", publicKey: key1.publicKey },
          { id: "key-2", publicKey: key2.publicKey },
        ],
      });

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(true);
      expect(result.checks.signature.status).toBe("pass");
    });

    it("should reject signature not from any trusted key", () => {
      const key1 = generateKeyPair();
      const key2 = generateKeyPair();
      const untrustedKey = generateKeyPair();

      // Sign with untrusted key
      const plugin = createSafeSignedPlugin(tempDir, untrustedKey, "untrusted");

      // Config only trusts key1 and key2
      const config = createStrictConfig({
        enableScanning: false,
        trustedKeys: [
          { id: "key-1", publicKey: key1.publicKey },
          { id: "key-2", publicKey: key2.publicKey },
        ],
      });

      const ctx = createVerifyContext(plugin, config);
      const result = verifyPluginSecurity(ctx);

      expect(result.ok).toBe(false);
      expect(result.reason).toContain("unknown signer");
    });
  });
});
