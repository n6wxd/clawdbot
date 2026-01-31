/**
 * Plugin Security Audit Logging
 *
 * Audit logging for plugin security events. Supports JSON Lines format
 * for easy parsing and analysis.
 */

import fs from "node:fs";
import path from "node:path";

import type {
  AuditConfig,
  AuditEvent,
  AuditEventType,
  AuditLogger,
  PluginOrigin,
  SecurityFinding,
  VerifyResult,
} from "./types.js";

// =============================================================================
// Audit Logger Implementation
// =============================================================================

/**
 * Create an audit logger instance.
 */
export function createAuditLogger(config: AuditConfig): AuditLogger {
  if (!config.enabled) {
    return createNoOpLogger();
  }

  const logPath = config.path ?? getDefaultAuditPath();
  const format = config.format ?? "jsonl";

  // Ensure directory exists
  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const buffer: AuditEvent[] = [];
  const maxBufferSize = 100;

  const logger: AuditLogger = {
    log(event) {
      const fullEvent: AuditEvent = {
        ...event,
        timestamp: new Date().toISOString(),
      };

      buffer.push(fullEvent);

      // Flush if buffer is full
      if (buffer.length >= maxBufferSize) {
        flushSync(logPath, buffer, format);
        buffer.length = 0;
      }
    },

    async flush() {
      if (buffer.length > 0) {
        await flushAsync(logPath, buffer, format);
        buffer.length = 0;
      }
    },
  };

  return logger;
}

/**
 * Create a no-op logger for when auditing is disabled.
 */
function createNoOpLogger(): AuditLogger {
  return {
    log() {
      // No-op
    },
    async flush() {
      // No-op
    },
  };
}

// =============================================================================
// Flush Operations
// =============================================================================

/**
 * Synchronously flush buffered events to log file.
 */
function flushSync(logPath: string, events: AuditEvent[], format: string): void {
  const content = formatEvents(events, format);
  fs.appendFileSync(logPath, content, { mode: 0o600 });
}

/**
 * Asynchronously flush buffered events to log file.
 */
async function flushAsync(logPath: string, events: AuditEvent[], format: string): Promise<void> {
  const content = formatEvents(events, format);
  await fs.promises.appendFile(logPath, content, { mode: 0o600 });
}

/**
 * Format events for output.
 */
function formatEvents(events: AuditEvent[], format: string): string {
  switch (format) {
    case "json":
      return JSON.stringify(events, null, 2) + "\n";
    case "jsonl":
      return events.map((e) => JSON.stringify(e)).join("\n") + "\n";
    case "text":
      return events.map(formatEventAsText).join("\n") + "\n";
    default:
      return events.map((e) => JSON.stringify(e)).join("\n") + "\n";
  }
}

/**
 * Format a single event as human-readable text.
 */
function formatEventAsText(event: AuditEvent): string {
  const time = event.timestamp.slice(11, 19); // HH:MM:SS
  const result = event.result.toUpperCase().padEnd(5);
  const type = event.eventType.padEnd(20);

  return `[${time}] ${result} ${type} ${event.pluginId} (${event.origin})`;
}

// =============================================================================
// Event Builders
// =============================================================================

/**
 * Create a load attempt audit event.
 */
export function createLoadAttemptEvent(params: {
  pluginId: string;
  source: string;
  origin: PluginOrigin;
  result: VerifyResult;
}): Omit<AuditEvent, "timestamp"> {
  return {
    eventType: "load_attempt",
    pluginId: params.pluginId,
    source: params.source,
    origin: params.origin,
    result: params.result.ok ? "allow" : "block",
    details: {
      trustLevel: params.result.level,
      checks: params.result.checks,
      reason: params.result.reason,
    },
  };
}

/**
 * Create a verification pass event.
 */
export function createVerificationPassEvent(params: {
  pluginId: string;
  source: string;
  origin: PluginOrigin;
  level: string;
}): Omit<AuditEvent, "timestamp"> {
  return {
    eventType: "verification_pass",
    pluginId: params.pluginId,
    source: params.source,
    origin: params.origin,
    result: "allow",
    details: {
      trustLevel: params.level,
    },
  };
}

/**
 * Create a verification failure event.
 */
export function createVerificationFailEvent(params: {
  pluginId: string;
  source: string;
  origin: PluginOrigin;
  reason: string;
  checks: VerifyResult["checks"];
}): Omit<AuditEvent, "timestamp"> {
  return {
    eventType: "verification_fail",
    pluginId: params.pluginId,
    source: params.source,
    origin: params.origin,
    result: "block",
    details: {
      reason: params.reason,
      checks: params.checks,
    },
  };
}

/**
 * Create a hash mismatch event.
 */
export function createHashMismatchEvent(params: {
  pluginId: string;
  source: string;
  origin: PluginOrigin;
  expected: string;
  actual: string;
}): Omit<AuditEvent, "timestamp"> {
  return {
    eventType: "hash_mismatch",
    pluginId: params.pluginId,
    source: params.source,
    origin: params.origin,
    result: "block",
    details: {
      expectedHash: params.expected,
      actualHash: params.actual,
    },
  };
}

/**
 * Create a signature invalid event.
 */
export function createSignatureInvalidEvent(params: {
  pluginId: string;
  source: string;
  origin: PluginOrigin;
  signedBy?: string;
  reason: string;
}): Omit<AuditEvent, "timestamp"> {
  return {
    eventType: "signature_invalid",
    pluginId: params.pluginId,
    source: params.source,
    origin: params.origin,
    result: "block",
    details: {
      signedBy: params.signedBy,
      reason: params.reason,
    },
  };
}

/**
 * Create a scan finding event.
 */
export function createScanFindingEvent(params: {
  pluginId: string;
  source: string;
  origin: PluginOrigin;
  finding: SecurityFinding;
}): Omit<AuditEvent, "timestamp"> {
  return {
    eventType: "scan_finding",
    pluginId: params.pluginId,
    source: params.source,
    origin: params.origin,
    result: params.finding.severity === "critical" ? "block" : "warn",
    details: {
      patternId: params.finding.id,
      severity: params.finding.severity,
      file: params.finding.file,
      line: params.finding.line,
      message: params.finding.message,
    },
  };
}

/**
 * Create a trust decision event.
 */
export function createTrustDecisionEvent(params: {
  pluginId: string;
  source: string;
  origin: PluginOrigin;
  decision: "allow" | "block" | "warn";
  reason: string;
  trustLevel: string;
}): Omit<AuditEvent, "timestamp"> {
  return {
    eventType: "trust_decision",
    pluginId: params.pluginId,
    source: params.source,
    origin: params.origin,
    result: params.decision,
    details: {
      reason: params.reason,
      trustLevel: params.trustLevel,
    },
  };
}

// =============================================================================
// Log Reading
// =============================================================================

/**
 * Read audit events from log file.
 */
export async function readAuditLog(logPath: string): Promise<AuditEvent[]> {
  if (!fs.existsSync(logPath)) {
    return [];
  }

  const content = await fs.promises.readFile(logPath, "utf-8");
  const lines = content.trim().split("\n").filter(Boolean);

  return lines.map((line) => JSON.parse(line) as AuditEvent);
}

/**
 * Filter audit events by criteria.
 */
export function filterAuditEvents(
  events: AuditEvent[],
  filter: {
    pluginId?: string;
    eventType?: AuditEventType;
    result?: "allow" | "block" | "warn";
    since?: Date;
    until?: Date;
  },
): AuditEvent[] {
  return events.filter((event) => {
    if (filter.pluginId && event.pluginId !== filter.pluginId) {
      return false;
    }
    if (filter.eventType && event.eventType !== filter.eventType) {
      return false;
    }
    if (filter.result && event.result !== filter.result) {
      return false;
    }
    if (filter.since) {
      const eventTime = new Date(event.timestamp);
      if (eventTime < filter.since) {
        return false;
      }
    }
    if (filter.until) {
      const eventTime = new Date(event.timestamp);
      if (eventTime > filter.until) {
        return false;
      }
    }
    return true;
  });
}

/**
 * Summarize audit events.
 */
export function summarizeAuditEvents(events: AuditEvent[]): {
  total: number;
  allowed: number;
  blocked: number;
  warned: number;
  byEventType: Record<string, number>;
  byPlugin: Record<string, number>;
} {
  const summary = {
    total: events.length,
    allowed: 0,
    blocked: 0,
    warned: 0,
    byEventType: {} as Record<string, number>,
    byPlugin: {} as Record<string, number>,
  };

  for (const event of events) {
    switch (event.result) {
      case "allow":
        summary.allowed++;
        break;
      case "block":
        summary.blocked++;
        break;
      case "warn":
        summary.warned++;
        break;
    }

    summary.byEventType[event.eventType] = (summary.byEventType[event.eventType] ?? 0) + 1;
    summary.byPlugin[event.pluginId] = (summary.byPlugin[event.pluginId] ?? 0) + 1;
  }

  return summary;
}

// =============================================================================
// Utilities
// =============================================================================

/**
 * Get default audit log path.
 */
function getDefaultAuditPath(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
  return path.join(home, ".openclaw", "audit", "plugins.jsonl");
}

/**
 * Rotate audit log if it exceeds size limit.
 */
export async function rotateAuditLog(
  logPath: string,
  maxSizeBytes: number = 10 * 1024 * 1024, // 10MB
): Promise<void> {
  if (!fs.existsSync(logPath)) {
    return;
  }

  const stats = await fs.promises.stat(logPath);
  if (stats.size < maxSizeBytes) {
    return;
  }

  // Rotate: current -> .1, .1 -> .2, etc.
  const maxRotations = 5;
  for (let i = maxRotations - 1; i >= 0; i--) {
    const current = i === 0 ? logPath : `${logPath}.${i}`;
    const next = `${logPath}.${i + 1}`;

    if (fs.existsSync(current)) {
      if (i === maxRotations - 1) {
        await fs.promises.unlink(current);
      } else {
        await fs.promises.rename(current, next);
      }
    }
  }
}

/**
 * Clean old audit logs based on retention period.
 */
export async function cleanOldAuditLogs(logPath: string, retentionDays: number): Promise<number> {
  const dir = path.dirname(logPath);
  const basename = path.basename(logPath);

  if (!fs.existsSync(dir)) {
    return 0;
  }

  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  let deleted = 0;

  const entries = await fs.promises.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.startsWith(basename)) {
      continue;
    }

    const filePath = path.join(dir, entry.name);
    const stats = await fs.promises.stat(filePath);

    if (stats.mtimeMs < cutoff) {
      await fs.promises.unlink(filePath);
      deleted++;
    }
  }

  return deleted;
}
