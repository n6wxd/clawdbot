/**
 * Plugin Security Module
 *
 * Core security verification for OpenClaw plugins.
 * Provides hash verification, signature verification, lockfile management,
 * static analysis scanning, and audit logging.
 */

// Types
export type {
  AuditConfig,
  AuditEvent,
  AuditEventType,
  AuditLogger,
  CheckResult,
  DirectoryHashOptions,
  HashAlgorithm,
  HashResult,
  LockedPlugin,
  PluginLockfile,
  PluginOrigin,
  PluginPermissions,
  PluginSecurityConfig,
  PluginSecurityManifest,
  SecurityFinding,
  SecurityPattern,
  SecuritySeverity,
  TrustLevel,
  TrustedKey,
  VerifyContext,
  VerifyResult,
} from "./types.js";

export { DEFAULT_SECURITY_CONFIG } from "./types.js";

// Hash verification
export {
  compareHashes,
  computeDirectoryHash,
  computeFileHash,
  computeHash,
  formatHash,
  isValidHash,
  parseHash,
  verifyDirectoryHash,
  verifyFileHash,
} from "./hash.js";

// Signature verification
export {
  computeKeyFingerprint,
  encodePublicKeyForConfig,
  findTrustedKey,
  generateKeyPair,
  getSignerId,
  hasSignature,
  loadPrivateKey,
  loadPublicKey,
  loadTrustedKeys,
  saveKeyPair,
  signManifest,
  verifyKeyId,
  verifyManifestSignature,
} from "./signature.js";

// Lockfile management
export {
  createLockfile,
  getDefaultLockfilePath,
  getDefaultSecretPath,
  getLockedPlugin,
  getPinnedPluginIds,
  getPluginsWithFindings,
  getStalePlugins,
  isPluginPinned,
  loadLockfile,
  loadOrCreateSecret,
  migrateLockfile,
  pinPlugin,
  saveLockfile,
  unpinPlugin,
  updateLastVerified,
  verifyLockfileHmac,
  verifyPluginAgainstLockfile,
} from "./lockfile.js";

// Static analysis
export {
  calculateRiskScore,
  formatFindingsReport,
  getHighestSeverity,
  getPatternsBySeverity,
  getSecurityPatterns,
  groupFindingsBySeverity,
  scanDirectory,
  scanFile,
  scanSource,
} from "./scanner.js";

// Audit logging
export {
  cleanOldAuditLogs,
  createAuditLogger,
  createHashMismatchEvent,
  createLoadAttemptEvent,
  createScanFindingEvent,
  createSignatureInvalidEvent,
  createTrustDecisionEvent,
  createVerificationFailEvent,
  createVerificationPassEvent,
  filterAuditEvents,
  readAuditLog,
  rotateAuditLog,
  summarizeAuditEvents,
} from "./audit.js";

// Main verification
export { normalizeSecurityConfig, verifyPluginSecurity } from "./verify.js";

// Benchmarking
export {
  formatBenchmarkReport,
  runBenchmarkCli,
  runBenchmarkSuite,
} from "./benchmark.js";

export type { BenchmarkOptions, BenchmarkResult, BenchmarkSuite } from "./benchmark.js";

// Re-export lockfile types
export type { LockfileVerifyResult } from "./lockfile.js";
