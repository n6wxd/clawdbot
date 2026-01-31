/**
 * Plugin Security Verification Orchestrator
 *
 * Main entry point for plugin security verification.
 * Orchestrates hash, signature, lockfile, and scan checks.
 */

import path from "node:path";

import type {
  AuditLogger,
  CheckResult,
  PluginSecurityConfig,
  PluginSecurityManifest,
  SecurityFinding,
  TrustLevel,
  VerifyContext,
  VerifyResult,
} from "./types.js";
import { DEFAULT_SECURITY_CONFIG } from "./types.js";
import { computeFileHash, verifyFileHashWithContent } from "./hash.js";
import {
  createHashMismatchEvent,
  createSignatureInvalidEvent,
  createTrustDecisionEvent,
  createVerificationFailEvent,
  createVerificationPassEvent,
} from "./audit.js";
import { verifyPluginAgainstLockfile } from "./lockfile.js";
import { findTrustedKey, hasSignature, loadTrustedKeys, verifyManifestSignature } from "./signature.js";
import { calculateRiskScore, getHighestSeverity, scanDirectory } from "./scanner.js";

// =============================================================================
// Main Verification
// =============================================================================

/**
 * Verify plugin security.
 *
 * This is the main entry point called by the plugin loader.
 */
export function verifyPluginSecurity(ctx: VerifyContext): VerifyResult {
  const config = ctx.config;

  // Skip verification if disabled
  if (config.mode === "off") {
    return createPassResult("unsigned", { hash: skip(), signature: skip(), lockfile: skip(), scan: skip() });
  }

  // Trust bundled plugins implicitly
  if (config.trustBundled && ctx.origin === "bundled") {
    logTrustDecision(ctx, "allow", "bundled plugin (implicitly trusted)", "verified");
    return createPassResult("verified", { hash: skip(), signature: skip(), lockfile: skip(), scan: skip() });
  }

  const checks: VerifyResult["checks"] = {
    hash: { status: "skip" },
    signature: { status: "skip" },
    lockfile: { status: "skip" },
    scan: { status: "skip" },
  };

  let trustLevel: TrustLevel = "unsigned";
  let findings: SecurityFinding[] = [];

  // Step 1: Hash verification
  const hashResult = verifyHash(ctx);
  checks.hash = hashResult.check;

  if (!hashResult.ok) {
    logVerificationFail(ctx, hashResult.reason ?? "hash verification failed", checks);
    return createFailResult(hashResult.reason ?? "hash verification failed", trustLevel, checks);
  }

  if (hashResult.check.status === "pass") {
    trustLevel = "hashed";
  }

  // Step 2: Signature verification
  const signatureResult = verifySignatureCheck(ctx);
  checks.signature = signatureResult.check;

  if (!signatureResult.ok && config.mode === "strict") {
    logVerificationFail(ctx, signatureResult.reason ?? "signature verification failed", checks);
    return createFailResult(signatureResult.reason ?? "signature verification required", trustLevel, checks);
  }

  if (signatureResult.check.status === "pass") {
    trustLevel = "signed";
  }

  // Step 3: Lockfile verification (if lockfile exists)
  if (ctx.lockfile) {
    const lockfileResult = verifyLockfileCheck(ctx);
    checks.lockfile = lockfileResult.check;

    if (!lockfileResult.ok) {
      logVerificationFail(ctx, lockfileResult.reason ?? "lockfile mismatch", checks);
      return createFailResult(lockfileResult.reason ?? "lockfile verification failed", trustLevel, checks);
    }
  }

  // Step 4: Static analysis scan (optional)
  if (config.enableScanning) {
    const scanResult = performScan(ctx);
    checks.scan = scanResult.check;
    findings = scanResult.findings;

    // Block on critical findings in strict mode
    if (config.mode === "strict" && scanResult.highestSeverity === "critical") {
      logVerificationFail(ctx, "critical security findings detected", checks);
      return createFailResult("critical security findings detected", trustLevel, checks, findings);
    }
  }

  // All checks passed
  if (signatureResult.check.status === "pass" && checks.lockfile.status !== "fail") {
    trustLevel = "verified";
  }

  logVerificationPass(ctx, trustLevel);

  return {
    ok: true,
    level: trustLevel,
    checks,
    findings: findings.length > 0 ? findings : undefined,
    // Pass through verified content for atomic use by loader (prevents TOCTOU)
    verifiedContent: hashResult.verifiedContent,
  };
}

// =============================================================================
// Individual Checks
// =============================================================================

type CheckReturn = {
  ok: boolean;
  reason?: string;
  check: CheckResult;
  /** Verified content for atomic use (prevents TOCTOU attacks) */
  verifiedContent?: {
    entryPath: string;
    content: Buffer;
  };
};

/**
 * Verify content hash.
 *
 * Uses atomic verify-and-return pattern to prevent TOCTOU attacks.
 * The verified content is returned for direct use by the loader.
 */
function verifyHash(ctx: VerifyContext): CheckReturn {
  const expectedHash = ctx.manifest.security?.contentHash;

  if (!expectedHash) {
    return {
      ok: true,
      check: { status: "skip", message: "no hash in manifest" },
    };
  }

  // Resolve entry point
  const entryPath = resolveEntryPoint(ctx.source);
  if (!entryPath) {
    return {
      ok: false,
      reason: "cannot resolve entry point",
      check: { status: "fail", message: "cannot resolve entry point" },
    };
  }

  // Use atomic verify-and-return to prevent TOCTOU attacks
  const result = verifyFileHashWithContent(entryPath, expectedHash);

  if (!result.valid) {
    logHashMismatch(ctx, expectedHash, result.actualHash.formatted);

    return {
      ok: false,
      reason: "content hash mismatch",
      check: {
        status: "fail",
        message: "content hash mismatch",
        details: { expected: expectedHash, actual: result.actualHash.formatted },
      },
    };
  }

  return {
    ok: true,
    check: { status: "pass", message: "hash verified" },
    // Return verified content for atomic use by loader
    verifiedContent: {
      entryPath,
      content: result.content!,
    },
  };
}

/**
 * Verify signature.
 */
function verifySignatureCheck(ctx: VerifyContext): CheckReturn {
  if (!hasSignature(ctx.manifest)) {
    return {
      ok: ctx.config.mode !== "strict",
      reason: ctx.config.mode === "strict" ? "signature required" : undefined,
      check: { status: "skip", message: "no signature in manifest" },
    };
  }

  const signedBy = ctx.manifest.security?.signedBy;
  const trustedKeys = loadTrustedKeys(ctx.config.trustedKeys);
  const publicKey = findTrustedKey(trustedKeys, signedBy);

  if (!publicKey) {
    logSignatureInvalid(ctx, signedBy, "unknown signer");
    return {
      ok: ctx.config.mode !== "strict",
      reason: `unknown signer: ${signedBy}`,
      check: { status: "warn", message: `unknown signer: ${signedBy}` },
    };
  }

  const result = verifyManifestSignature(ctx.manifest, publicKey);

  if (!result.ok) {
    logSignatureInvalid(ctx, signedBy, result.reason ?? "invalid signature");
    return {
      ok: false,
      reason: result.reason,
      check: { status: "fail", message: result.reason ?? "signature invalid" },
    };
  }

  return {
    ok: true,
    check: { status: "pass", message: `signed by ${signedBy}` },
  };
}

/**
 * Verify against lockfile.
 */
function verifyLockfileCheck(ctx: VerifyContext): CheckReturn {
  if (!ctx.lockfile) {
    return {
      ok: true,
      check: { status: "skip", message: "no lockfile" },
    };
  }

  const entryPath = resolveEntryPoint(ctx.source);
  if (!entryPath) {
    return {
      ok: true,
      check: { status: "skip", message: "cannot resolve entry point" },
    };
  }

  const contentHash = computeFileHash(entryPath).formatted;
  const manifestHash = computeFileHash(ctx.source).formatted;

  const result = verifyPluginAgainstLockfile(ctx.lockfile, {
    id: ctx.pluginId,
    version: ctx.manifest.version,
    source: ctx.source,
    contentHash,
    manifestHash,
  });

  if (!result.found) {
    return {
      ok: true,
      check: { status: "warn", message: "plugin not in lockfile" },
    };
  }

  if (!result.ok) {
    return {
      ok: false,
      reason: result.reason,
      check: {
        status: "fail",
        message: result.reason ?? "lockfile mismatch",
        details: result.mismatches,
      },
    };
  }

  return {
    ok: true,
    check: { status: "pass", message: "matches lockfile" },
  };
}

/**
 * Perform static analysis scan.
 */
function performScan(ctx: VerifyContext): {
  check: CheckResult;
  findings: SecurityFinding[];
  highestSeverity: string;
} {
  const pluginDir = path.dirname(ctx.source);
  const findings = scanDirectory(pluginDir);
  const { score, verdict } = calculateRiskScore(findings);
  const highestSeverity = getHighestSeverity(findings);

  if (findings.length === 0) {
    return {
      check: { status: "pass", message: "no findings" },
      findings: [],
      highestSeverity: "none",
    };
  }

  const status = verdict === "unsafe" ? "fail" : verdict === "caution" ? "warn" : "pass";

  return {
    check: {
      status,
      message: `${findings.length} findings (score: ${score})`,
      details: { score, verdict, highestSeverity },
    },
    findings,
    highestSeverity,
  };
}

// =============================================================================
// Helpers
// =============================================================================

function skip(): CheckResult {
  return { status: "skip" };
}

function createPassResult(level: TrustLevel, checks: VerifyResult["checks"]): VerifyResult {
  return { ok: true, level, checks };
}

function createFailResult(
  reason: string,
  level: TrustLevel,
  checks: VerifyResult["checks"],
  findings?: SecurityFinding[],
): VerifyResult {
  return { ok: false, level, reason, checks, findings };
}

/**
 * Resolve entry point path from manifest path.
 */
function resolveEntryPoint(manifestPath: string): string | null {
  const dir = path.dirname(manifestPath);

  // Try common entry points
  const candidates = ["index.js", "index.ts", "index.mjs", "src/index.js", "src/index.ts"];

  for (const candidate of candidates) {
    const fullPath = path.join(dir, candidate);
    try {
      const fs = require("node:fs");
      if (fs.existsSync(fullPath)) {
        return fullPath;
      }
    } catch {
      // Continue
    }
  }

  return null;
}

// =============================================================================
// Audit Logging Helpers
// =============================================================================

function logVerificationPass(ctx: VerifyContext, level: TrustLevel): void {
  ctx.auditLogger?.log(
    createVerificationPassEvent({
      pluginId: ctx.pluginId,
      source: ctx.source,
      origin: ctx.origin,
      level,
    }),
  );
}

function logVerificationFail(ctx: VerifyContext, reason: string, checks: VerifyResult["checks"]): void {
  ctx.auditLogger?.log(
    createVerificationFailEvent({
      pluginId: ctx.pluginId,
      source: ctx.source,
      origin: ctx.origin,
      reason,
      checks,
    }),
  );
}

function logHashMismatch(ctx: VerifyContext, expected: string, actual: string): void {
  ctx.auditLogger?.log(
    createHashMismatchEvent({
      pluginId: ctx.pluginId,
      source: ctx.source,
      origin: ctx.origin,
      expected,
      actual,
    }),
  );
}

function logSignatureInvalid(ctx: VerifyContext, signedBy: string | undefined, reason: string): void {
  ctx.auditLogger?.log(
    createSignatureInvalidEvent({
      pluginId: ctx.pluginId,
      source: ctx.source,
      origin: ctx.origin,
      signedBy,
      reason,
    }),
  );
}

function logTrustDecision(
  ctx: VerifyContext,
  decision: "allow" | "block" | "warn",
  reason: string,
  trustLevel: TrustLevel,
): void {
  ctx.auditLogger?.log(
    createTrustDecisionEvent({
      pluginId: ctx.pluginId,
      source: ctx.source,
      origin: ctx.origin,
      decision,
      reason,
      trustLevel,
    }),
  );
}

// =============================================================================
// Configuration Helpers
// =============================================================================

/**
 * Normalize security configuration with defaults.
 */
export function normalizeSecurityConfig(
  config?: Partial<PluginSecurityConfig>,
): PluginSecurityConfig {
  return {
    ...DEFAULT_SECURITY_CONFIG,
    ...config,
    audit: {
      ...DEFAULT_SECURITY_CONFIG.audit,
      ...config?.audit,
    },
  };
}
