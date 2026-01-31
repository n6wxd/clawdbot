/**
 * Plugin Signature Verification
 *
 * Ed25519 signature verification for plugin authenticity.
 * Uses Node.js built-in crypto module.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import type { PluginSecurityManifest, TrustedKey } from "./types.js";

const KEY_TYPE = "ed25519";

// =============================================================================
// Signature Verification
// =============================================================================

/**
 * Verify a plugin manifest signature.
 */
export function verifyManifestSignature(
  manifest: {
    id: string;
    version?: string;
    security?: PluginSecurityManifest;
  },
  publicKeyPem: string,
): { ok: boolean; reason?: string } {
  const security = manifest.security;

  if (!security?.signature) {
    return { ok: false, reason: "no signature in manifest" };
  }

  try {
    // Create canonical manifest data (excluding signature)
    const canonicalData = createCanonicalManifestData(manifest);

    // Decode signature
    const signatureBuffer = Buffer.from(security.signature, "base64");

    // Create public key
    const publicKey = createPublicKey({
      key: publicKeyPem,
      format: "pem",
    });

    // Verify signature
    const isValid = verify(null, Buffer.from(canonicalData), publicKey, signatureBuffer);

    if (!isValid) {
      return { ok: false, reason: "signature verification failed" };
    }

    return { ok: true };
  } catch (err) {
    return { ok: false, reason: `signature error: ${String(err)}` };
  }
}

/**
 * Create canonical manifest data for signing/verification.
 * Excludes the signature field and sorts keys deterministically.
 */
function createCanonicalManifestData(manifest: {
  id: string;
  version?: string;
  security?: PluginSecurityManifest;
}): string {
  // Create a copy without the signature
  const forSigning: Record<string, unknown> = {
    id: manifest.id,
  };

  if (manifest.version) {
    forSigning.version = manifest.version;
  }

  if (manifest.security) {
    const securityCopy: Record<string, unknown> = {};

    if (manifest.security.contentHash) {
      securityCopy.contentHash = manifest.security.contentHash;
    }
    if (manifest.security.directoryHash) {
      securityCopy.directoryHash = manifest.security.directoryHash;
    }
    if (manifest.security.signedBy) {
      securityCopy.signedBy = manifest.security.signedBy;
    }
    if (manifest.security.requiredTrust) {
      securityCopy.requiredTrust = manifest.security.requiredTrust;
    }
    if (manifest.security.permissions) {
      securityCopy.permissions = manifest.security.permissions;
    }

    if (Object.keys(securityCopy).length > 0) {
      forSigning.security = securityCopy;
    }
  }

  // Sort keys recursively and stringify
  return JSON.stringify(sortObjectKeys(forSigning));
}

/**
 * Recursively sort object keys for deterministic serialization.
 */
function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys);
  }

  const sorted: Record<string, unknown> = {};
  const keys = Object.keys(obj as Record<string, unknown>).sort();

  for (const key of keys) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }

  return sorted;
}

// =============================================================================
// Trusted Key Management
// =============================================================================

/**
 * Load trusted keys from configuration.
 */
export function loadTrustedKeys(keys: TrustedKey[]): Map<string, string> {
  const keyMap = new Map<string, string>();

  for (const key of keys) {
    try {
      const pem = decodePublicKey(key.publicKey);
      keyMap.set(key.id, pem);
    } catch {
      // Skip invalid keys
    }
  }

  return keyMap;
}

/**
 * Decode public key from various formats to PEM.
 */
function decodePublicKey(encoded: string): string {
  // Already PEM format
  if (encoded.startsWith("-----BEGIN")) {
    return encoded;
  }

  // Base64 encoded raw key (with or without prefix)
  let base64 = encoded;
  if (encoded.startsWith("base64:")) {
    base64 = encoded.slice(7);
  }

  // Decode and wrap in PEM
  const keyBuffer = Buffer.from(base64, "base64");

  // Check if it's DER-encoded SubjectPublicKeyInfo
  if (keyBuffer.length > 32) {
    // Likely DER format, create PEM directly
    return (
      "-----BEGIN PUBLIC KEY-----\n" +
      base64.match(/.{1,64}/g)?.join("\n") +
      "\n-----END PUBLIC KEY-----"
    );
  }

  // Raw 32-byte Ed25519 public key - wrap in SPKI format
  const spkiPrefix = Buffer.from([
    0x30, 0x2a, // SEQUENCE, length 42
    0x30, 0x05, // SEQUENCE, length 5
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x03, 0x21, 0x00, // BIT STRING, length 33, no unused bits
  ]);

  const spki = Buffer.concat([spkiPrefix, keyBuffer]);
  const spkiBase64 = spki.toString("base64");

  return (
    "-----BEGIN PUBLIC KEY-----\n" +
    spkiBase64.match(/.{1,64}/g)?.join("\n") +
    "\n-----END PUBLIC KEY-----"
  );
}

/**
 * Find trusted key by ID.
 */
export function findTrustedKey(
  keys: Map<string, string>,
  keyId: string | undefined,
): string | undefined {
  if (!keyId) {
    return undefined;
  }
  return keys.get(keyId);
}

// =============================================================================
// Signing (for plugin authors)
// =============================================================================

/**
 * Generate a new Ed25519 key pair for signing.
 */
export function generateKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync(KEY_TYPE, {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return { publicKey, privateKey };
}

/**
 * Sign a plugin manifest.
 */
export function signManifest(
  manifest: {
    id: string;
    version?: string;
    security?: PluginSecurityManifest;
  },
  privateKeyPem: string,
): string {
  const canonicalData = createCanonicalManifestData(manifest);

  const privateKey = createPrivateKey({
    key: privateKeyPem,
    format: "pem",
  });

  const signature = sign(null, Buffer.from(canonicalData), privateKey);

  return signature.toString("base64");
}

/**
 * Save key pair to files.
 */
export function saveKeyPair(
  outputDir: string,
  keyId: string,
  keys: { publicKey: string; privateKey: string },
): { publicKeyPath: string; privateKeyPath: string } {
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  }

  const publicKeyPath = path.join(outputDir, `${keyId}.pub`);
  const privateKeyPath = path.join(outputDir, `${keyId}.key`);

  fs.writeFileSync(publicKeyPath, keys.publicKey, { mode: 0o644 });
  fs.writeFileSync(privateKeyPath, keys.privateKey, { mode: 0o600 });

  return { publicKeyPath, privateKeyPath };
}

/**
 * Load private key from file.
 */
export function loadPrivateKey(keyPath: string): string {
  return fs.readFileSync(keyPath, "utf-8");
}

/**
 * Load public key from file.
 */
export function loadPublicKey(keyPath: string): string {
  return fs.readFileSync(keyPath, "utf-8");
}

// =============================================================================
// Key Fingerprinting
// =============================================================================

/**
 * Compute fingerprint of a public key.
 */
export function computeKeyFingerprint(publicKeyPem: string): string {
  // Extract raw key bytes
  const publicKey = createPublicKey({
    key: publicKeyPem,
    format: "pem",
  });

  const exported = publicKey.export({ type: "spki", format: "der" });
  const hash = createHash("sha256").update(exported).digest("hex");

  // Format as fingerprint (groups of 4)
  return hash.match(/.{1,4}/g)?.join(":") ?? hash;
}

/**
 * Verify that a key ID matches a public key fingerprint.
 */
export function verifyKeyId(keyId: string, publicKeyPem: string): boolean {
  const fingerprint = computeKeyFingerprint(publicKeyPem);
  // Key ID can be a prefix of the fingerprint
  return fingerprint.startsWith(keyId.replace(/:/g, ""));
}

// =============================================================================
// Utilities
// =============================================================================

/**
 * Check if a manifest has a signature.
 */
export function hasSignature(manifest: { security?: PluginSecurityManifest }): boolean {
  return Boolean(manifest.security?.signature);
}

/**
 * Get signer ID from manifest.
 */
export function getSignerId(manifest: { security?: PluginSecurityManifest }): string | undefined {
  return manifest.security?.signedBy;
}

/**
 * Encode public key for configuration.
 */
export function encodePublicKeyForConfig(publicKeyPem: string): string {
  // Extract base64 content from PEM
  const lines = publicKeyPem.split("\n");
  const base64Lines = lines.filter((line) => !line.startsWith("-----"));
  return "base64:" + base64Lines.join("");
}
