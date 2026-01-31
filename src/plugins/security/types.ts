/**
 * Plugin Security Types
 *
 * Type definitions for the plugin security verification system.
 */

import type { PluginOrigin } from "../types.js";

// Re-export for use by other security module files
export type { PluginOrigin };

// =============================================================================
// Trust Levels
// =============================================================================

/**
 * Trust level assigned to a plugin based on verification status.
 */
export type TrustLevel = "unsigned" | "hashed" | "signed" | "verified";

// =============================================================================
// Security Configuration
// =============================================================================

/**
 * Security configuration for plugin loading.
 */
export type PluginSecurityConfig = {
  /**
   * Verification mode:
   * - "strict": Block unsigned plugins (except bundled)
   * - "permissive": Warn but allow unsigned plugins
   * - "off": No verification (not recommended)
   */
  mode: "strict" | "permissive" | "off";

  /**
   * Trust bundled plugins implicitly without verification.
   */
  trustBundled: boolean;

  /**
   * Trusted public keys for signature verification.
   */
  trustedKeys: TrustedKey[];

  /**
   * Lockfile path. Default: ~/.openclaw/plugins.lock
   */
  lockfilePath?: string;

  /**
   * Enable static analysis scanning.
   */
  enableScanning: boolean;

  /**
   * Path to security patterns file. Default: built-in patterns.
   */
  patternsPath?: string;

  /**
   * Audit logging configuration.
   */
  audit: AuditConfig;
};

/**
 * Trusted public key for signature verification.
 */
export type TrustedKey = {
  /** Unique identifier for this key */
  id: string;

  /** Base64-encoded Ed25519 public key */
  publicKey: string;

  /** Human-readable description */
  description?: string;
};

/**
 * Audit logging configuration.
 */
export type AuditConfig = {
  /** Enable audit logging */
  enabled: boolean;

  /** Path to audit log file. Default: ~/.openclaw/audit/plugins.jsonl */
  path?: string;

  /** Log format */
  format: "json" | "jsonl" | "text";

  /** Retention period in days */
  retention?: number;
};

// =============================================================================
// Manifest Security Extension
// =============================================================================

/**
 * Security metadata in plugin manifest.
 */
export type PluginSecurityManifest = {
  /** SHA-256 hash of entry point file content */
  contentHash?: string;

  /** SHA-256 hash of all source files (deterministic) */
  directoryHash?: string;

  /** Ed25519 signature of canonical manifest JSON (excluding signature) */
  signature?: string;

  /** Public key identifier (matches trustedKeys config) */
  signedBy?: string;

  /** Minimum trust level required to load */
  requiredTrust?: TrustLevel;

  /** Declared permissions (for maslahah test) */
  permissions?: PluginPermissions;
};

/**
 * Plugin permission declarations.
 */
export type PluginPermissions = {
  filesystem?: {
    read?: string[];
    write?: string[];
  };
  network?: {
    outbound?: string[];
    inbound?: boolean;
  };
  env?: string[];
  exec?: string[];
};

// =============================================================================
// Lockfile
// =============================================================================

/**
 * Plugin lockfile for integrity verification.
 */
export type PluginLockfile = {
  /** Lockfile format version */
  version: 2;

  /** Generation timestamp */
  generatedAt: string;

  /** HMAC-SHA256 of plugins data for tamper detection */
  hmac: string;

  /** Locked plugin entries */
  plugins: Record<string, LockedPlugin>;
};

/**
 * Individual locked plugin entry.
 */
export type LockedPlugin = {
  /** Plugin version */
  version: string;

  /** Source path */
  source: string;

  /** Origin (bundled, global, workspace, config) */
  origin: PluginOrigin;

  /** SHA-256 hash of entry point content */
  contentHash: string;

  /** SHA-256 hash of manifest */
  manifestHash: string;

  /** Whether signature was verified at pin time */
  signatureVerified: boolean;

  /** Key ID used for signing (if signed) */
  signedBy?: string;

  /** When plugin was pinned */
  pinnedAt: string;

  /** Last verification timestamp */
  lastVerified: string;

  /** Number of security findings at pin time */
  scanFindings?: number;

  /** Highest severity finding at pin time */
  scanHighest?: SecuritySeverity | "none";
};

// =============================================================================
// Verification Results
// =============================================================================

/**
 * Result of plugin security verification.
 */
export type VerifyResult = {
  /** Whether verification passed */
  ok: boolean;

  /** Assigned trust level */
  level: TrustLevel;

  /** Reason for failure (if !ok) */
  reason?: string;

  /** Individual check results */
  checks: {
    hash: CheckResult;
    signature: CheckResult;
    lockfile: CheckResult;
    scan: CheckResult;
  };

  /** Security findings from static analysis */
  findings?: SecurityFinding[];

  /** Audit event ID for this verification */
  auditId?: string;

  /**
   * Verified entry point content.
   * This content was read atomically during hash verification to prevent
   * TOCTOU (time-of-check-time-of-use) attacks. The loader should use this
   * content directly instead of re-reading from disk.
   */
  verifiedContent?: {
    /** Path to the entry point file */
    entryPath: string;
    /** File content that was verified */
    content: Buffer;
  };
};

/**
 * Result of an individual security check.
 */
export type CheckResult = {
  /** Check status */
  status: "pass" | "fail" | "skip" | "warn";

  /** Human-readable message */
  message?: string;

  /** Additional details */
  details?: Record<string, unknown>;
};

// =============================================================================
// Security Findings
// =============================================================================

/**
 * Severity levels for security findings.
 */
export type SecuritySeverity = "critical" | "high" | "medium" | "low";

/**
 * Security finding from static analysis.
 */
export type SecurityFinding = {
  /** Pattern ID that matched */
  id: string;

  /** Severity level */
  severity: SecuritySeverity;

  /** File where finding was detected */
  file: string;

  /** Line number (if available) */
  line?: number;

  /** Matched text */
  match?: string;

  /** Human-readable message */
  message: string;

  /** Context lines around the match */
  context?: string[];
};

/**
 * Security pattern for static analysis.
 */
export type SecurityPattern = {
  /** Unique pattern ID */
  id: string;

  /** Human-readable name */
  name: string;

  /** Severity level */
  severity: SecuritySeverity;

  /** Description of what this pattern detects */
  description: string;

  /** Regex patterns to match */
  patterns: string[];

  /** Context where this pattern applies */
  context: "code" | "content" | "filesystem_read" | "network";

  /** Permission that would make this pattern acceptable */
  requires_permission?: string;
};

// =============================================================================
// Audit Events
// =============================================================================

/**
 * Types of audit events.
 */
export type AuditEventType =
  | "load_attempt"
  | "verification_pass"
  | "verification_fail"
  | "hash_mismatch"
  | "signature_invalid"
  | "signature_missing"
  | "lockfile_mismatch"
  | "lockfile_missing"
  | "scan_finding"
  | "trust_decision"
  | "plugin_blocked"
  | "plugin_allowed";

/**
 * Audit event for security logging.
 */
export type AuditEvent = {
  /** Event timestamp (ISO 8601) */
  timestamp: string;

  /** Event type */
  eventType: AuditEventType;

  /** Plugin ID */
  pluginId: string;

  /** Plugin source path */
  source: string;

  /** Plugin origin */
  origin: PluginOrigin;

  /** Event result */
  result: "allow" | "block" | "warn";

  /** Additional event details */
  details: Record<string, unknown>;
};

// =============================================================================
// Hash Types
// =============================================================================

/**
 * Hash algorithm used for content hashing.
 */
export type HashAlgorithm = "sha256";

/**
 * Hash result with algorithm prefix.
 */
export type HashResult = {
  /** Hash algorithm used */
  algorithm: HashAlgorithm;

  /** Hex-encoded hash value */
  hash: string;

  /** Formatted hash string (algorithm:hash) */
  formatted: string;
};

/**
 * Options for directory hashing.
 */
export type DirectoryHashOptions = {
  /** File extensions to include. Default: [".js", ".ts", ".mjs", ".cjs", ".json"] */
  extensions?: string[];

  /** Patterns to exclude */
  exclude?: string[];

  /** Include hidden files (starting with .) */
  includeHidden?: boolean;
};

// =============================================================================
// Verification Context
// =============================================================================

/**
 * Context passed to security verification.
 */
export type VerifyContext = {
  /** Plugin ID */
  pluginId: string;

  /** Plugin source path */
  source: string;

  /** Plugin origin */
  origin: PluginOrigin;

  /** Plugin manifest with security metadata */
  manifest: {
    id: string;
    version?: string;
    security?: PluginSecurityManifest;
  };

  /** Security configuration */
  config: PluginSecurityConfig;

  /** Loaded lockfile (if available) */
  lockfile?: PluginLockfile;

  /** Audit logger (if enabled) */
  auditLogger?: AuditLogger;
};

/**
 * Audit logger interface.
 */
export type AuditLogger = {
  log: (event: Omit<AuditEvent, "timestamp">) => void;
  flush: () => Promise<void>;
};

// =============================================================================
// Defaults
// =============================================================================

/**
 * Default security configuration.
 */
export const DEFAULT_SECURITY_CONFIG: PluginSecurityConfig = {
  mode: "permissive",
  trustBundled: true,
  trustedKeys: [],
  enableScanning: true,
  audit: {
    enabled: true,
    format: "jsonl",
    retention: 90,
  },
};
