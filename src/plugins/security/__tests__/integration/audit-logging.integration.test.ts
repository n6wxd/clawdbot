/**
 * Audit Logging Integration Tests
 *
 * Tests event tracking, JSONL output, and event filtering.
 */

import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
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
} from "../../audit.js";
import { verifyPluginSecurity } from "../../verify.js";
import type { AuditConfig, AuditEvent, SecurityFinding, VerifyResult } from "../../types.js";
import {
  cleanupTempDir,
  createCapturingAuditLogger,
  createMaliciousCodeExecPlugin,
  createPermissiveConfig,
  createSafePlugin,
  createStrictConfig,
  createTamperedPlugin,
  createTempDir,
  createVerifyContext,
} from "./setup.js";

describe("audit-logging", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir("audit-test-");
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("audit logger creation", () => {
    it("should create functioning logger when enabled", () => {
      const logPath = path.join(tempDir, "audit.jsonl");
      const config: AuditConfig = {
        enabled: true,
        path: logPath,
        format: "jsonl",
      };

      const logger = createAuditLogger(config);

      logger.log({
        eventType: "load_attempt",
        pluginId: "test-plugin",
        source: "/path/to/plugin",
        origin: "workspace",
        result: "allow",
        details: { test: true },
      });

      // Manually flush
      logger.flush();
    });

    it("should create no-op logger when disabled", async () => {
      const logPath = path.join(tempDir, "audit.jsonl");
      const config: AuditConfig = {
        enabled: false,
        path: logPath,
        format: "jsonl",
      };

      const logger = createAuditLogger(config);

      logger.log({
        eventType: "load_attempt",
        pluginId: "test-plugin",
        source: "/path/to/plugin",
        origin: "workspace",
        result: "allow",
        details: {},
      });

      await logger.flush();

      // File should not be created
      expect(fs.existsSync(logPath)).toBe(false);
    });

    it("should create parent directory if needed", async () => {
      const logPath = path.join(tempDir, "nested", "dir", "audit.jsonl");
      const config: AuditConfig = {
        enabled: true,
        path: logPath,
        format: "jsonl",
      };

      const logger = createAuditLogger(config);

      logger.log({
        eventType: "load_attempt",
        pluginId: "test-plugin",
        source: "/path",
        origin: "workspace",
        result: "allow",
        details: {},
      });

      await logger.flush();

      expect(fs.existsSync(logPath)).toBe(true);
    });
  });

  describe("JSONL output format", () => {
    it("should write events in JSONL format", async () => {
      const logPath = path.join(tempDir, "audit.jsonl");
      const config: AuditConfig = {
        enabled: true,
        path: logPath,
        format: "jsonl",
      };

      const logger = createAuditLogger(config);

      logger.log({
        eventType: "verification_pass",
        pluginId: "plugin-1",
        source: "/path/1",
        origin: "workspace",
        result: "allow",
        details: { level: "signed" },
      });

      logger.log({
        eventType: "verification_fail",
        pluginId: "plugin-2",
        source: "/path/2",
        origin: "global",
        result: "block",
        details: { reason: "hash mismatch" },
      });

      await logger.flush();

      const content = fs.readFileSync(logPath, "utf-8");
      const lines = content.trim().split("\n");

      expect(lines).toHaveLength(2);

      const event1 = JSON.parse(lines[0]);
      expect(event1.eventType).toBe("verification_pass");
      expect(event1.pluginId).toBe("plugin-1");
      expect(event1.timestamp).toBeTruthy();

      const event2 = JSON.parse(lines[1]);
      expect(event2.eventType).toBe("verification_fail");
      expect(event2.pluginId).toBe("plugin-2");
    });

    it("should include ISO timestamps", async () => {
      const logPath = path.join(tempDir, "audit.jsonl");
      const config: AuditConfig = {
        enabled: true,
        path: logPath,
        format: "jsonl",
      };

      const logger = createAuditLogger(config);

      logger.log({
        eventType: "load_attempt",
        pluginId: "test",
        source: "/path",
        origin: "workspace",
        result: "allow",
        details: {},
      });

      await logger.flush();

      const events = await readAuditLog(logPath);
      expect(events).toHaveLength(1);

      const timestamp = new Date(events[0].timestamp);
      expect(timestamp.toString()).not.toBe("Invalid Date");
    });
  });

  describe("event builders", () => {
    it("should create load attempt event", () => {
      const result: VerifyResult = {
        ok: true,
        level: "signed",
        checks: {
          hash: { status: "pass" },
          signature: { status: "pass" },
          lockfile: { status: "skip" },
          scan: { status: "pass" },
        },
      };

      const event = createLoadAttemptEvent({
        pluginId: "my-plugin",
        source: "/path/to/plugin",
        origin: "workspace",
        result,
      });

      expect(event.eventType).toBe("load_attempt");
      expect(event.pluginId).toBe("my-plugin");
      expect(event.result).toBe("allow");
      expect(event.details.trustLevel).toBe("signed");
    });

    it("should create verification pass event", () => {
      const event = createVerificationPassEvent({
        pluginId: "test-plugin",
        source: "/path",
        origin: "global",
        level: "verified",
      });

      expect(event.eventType).toBe("verification_pass");
      expect(event.result).toBe("allow");
      expect(event.details.trustLevel).toBe("verified");
    });

    it("should create verification fail event", () => {
      const event = createVerificationFailEvent({
        pluginId: "bad-plugin",
        source: "/path",
        origin: "config",
        reason: "signature invalid",
        checks: {
          hash: { status: "pass" },
          signature: { status: "fail", message: "invalid signature" },
          lockfile: { status: "skip" },
          scan: { status: "skip" },
        },
      });

      expect(event.eventType).toBe("verification_fail");
      expect(event.result).toBe("block");
      expect(event.details.reason).toBe("signature invalid");
    });

    it("should create hash mismatch event", () => {
      const event = createHashMismatchEvent({
        pluginId: "tampered-plugin",
        source: "/path",
        origin: "workspace",
        expected: "sha256:aaa",
        actual: "sha256:bbb",
      });

      expect(event.eventType).toBe("hash_mismatch");
      expect(event.result).toBe("block");
      expect(event.details.expectedHash).toBe("sha256:aaa");
      expect(event.details.actualHash).toBe("sha256:bbb");
    });

    it("should create signature invalid event", () => {
      const event = createSignatureInvalidEvent({
        pluginId: "forged-plugin",
        source: "/path",
        origin: "workspace",
        signedBy: "unknown-key",
        reason: "unknown signer",
      });

      expect(event.eventType).toBe("signature_invalid");
      expect(event.result).toBe("block");
      expect(event.details.signedBy).toBe("unknown-key");
    });

    it("should create scan finding event", () => {
      const finding: SecurityFinding = {
        id: "CRED_EXFIL_001",
        severity: "critical",
        file: "/path/to/file.js",
        line: 42,
        message: "Credential exfiltration detected",
      };

      const event = createScanFindingEvent({
        pluginId: "malicious-plugin",
        source: "/path",
        origin: "workspace",
        finding,
      });

      expect(event.eventType).toBe("scan_finding");
      expect(event.result).toBe("block"); // Critical = block
      expect(event.details.patternId).toBe("CRED_EXFIL_001");
      expect(event.details.severity).toBe("critical");
    });

    it("should create trust decision event", () => {
      const event = createTrustDecisionEvent({
        pluginId: "trusted-plugin",
        source: "/path",
        origin: "bundled",
        decision: "allow",
        reason: "bundled plugin",
        trustLevel: "verified",
      });

      expect(event.eventType).toBe("trust_decision");
      expect(event.result).toBe("allow");
      expect(event.details.reason).toBe("bundled plugin");
    });
  });

  describe("event filtering", () => {
    const createTestEvents = (): AuditEvent[] => [
      {
        timestamp: "2024-01-01T10:00:00Z",
        eventType: "verification_pass",
        pluginId: "plugin-a",
        source: "/a",
        origin: "workspace",
        result: "allow",
        details: {},
      },
      {
        timestamp: "2024-01-01T11:00:00Z",
        eventType: "verification_fail",
        pluginId: "plugin-b",
        source: "/b",
        origin: "global",
        result: "block",
        details: {},
      },
      {
        timestamp: "2024-01-02T10:00:00Z",
        eventType: "verification_pass",
        pluginId: "plugin-a",
        source: "/a",
        origin: "workspace",
        result: "allow",
        details: {},
      },
      {
        timestamp: "2024-01-02T11:00:00Z",
        eventType: "scan_finding",
        pluginId: "plugin-c",
        source: "/c",
        origin: "config",
        result: "warn",
        details: {},
      },
    ];

    it("should filter by plugin ID", () => {
      const events = createTestEvents();
      const filtered = filterAuditEvents(events, { pluginId: "plugin-a" });

      expect(filtered).toHaveLength(2);
      expect(filtered.every((e) => e.pluginId === "plugin-a")).toBe(true);
    });

    it("should filter by event type", () => {
      const events = createTestEvents();
      const filtered = filterAuditEvents(events, { eventType: "verification_pass" });

      expect(filtered).toHaveLength(2);
      expect(filtered.every((e) => e.eventType === "verification_pass")).toBe(true);
    });

    it("should filter by result", () => {
      const events = createTestEvents();
      const filtered = filterAuditEvents(events, { result: "block" });

      expect(filtered).toHaveLength(1);
      expect(filtered[0].pluginId).toBe("plugin-b");
    });

    it("should filter by date range", () => {
      const events = createTestEvents();
      const filtered = filterAuditEvents(events, {
        since: new Date("2024-01-02T00:00:00Z"),
      });

      expect(filtered).toHaveLength(2);
    });

    it("should combine multiple filters", () => {
      const events = createTestEvents();
      const filtered = filterAuditEvents(events, {
        pluginId: "plugin-a",
        eventType: "verification_pass",
        since: new Date("2024-01-02T00:00:00Z"),
      });

      expect(filtered).toHaveLength(1);
      expect(filtered[0].timestamp).toBe("2024-01-02T10:00:00Z");
    });
  });

  describe("event summarization", () => {
    it("should summarize events correctly", () => {
      const events: AuditEvent[] = [
        {
          timestamp: "2024-01-01T10:00:00Z",
          eventType: "verification_pass",
          pluginId: "plugin-a",
          source: "/a",
          origin: "workspace",
          result: "allow",
          details: {},
        },
        {
          timestamp: "2024-01-01T10:01:00Z",
          eventType: "verification_pass",
          pluginId: "plugin-b",
          source: "/b",
          origin: "workspace",
          result: "allow",
          details: {},
        },
        {
          timestamp: "2024-01-01T10:02:00Z",
          eventType: "verification_fail",
          pluginId: "plugin-c",
          source: "/c",
          origin: "workspace",
          result: "block",
          details: {},
        },
        {
          timestamp: "2024-01-01T10:03:00Z",
          eventType: "scan_finding",
          pluginId: "plugin-a",
          source: "/a",
          origin: "workspace",
          result: "warn",
          details: {},
        },
      ];

      const summary = summarizeAuditEvents(events);

      expect(summary.total).toBe(4);
      expect(summary.allowed).toBe(2);
      expect(summary.blocked).toBe(1);
      expect(summary.warned).toBe(1);
      expect(summary.byEventType["verification_pass"]).toBe(2);
      expect(summary.byEventType["verification_fail"]).toBe(1);
      expect(summary.byEventType["scan_finding"]).toBe(1);
      expect(summary.byPlugin["plugin-a"]).toBe(2);
      expect(summary.byPlugin["plugin-b"]).toBe(1);
      expect(summary.byPlugin["plugin-c"]).toBe(1);
    });
  });

  describe("log rotation", () => {
    it("should rotate log when exceeding size limit", async () => {
      const logPath = path.join(tempDir, "audit.jsonl");

      // Create a large log file
      const largeContent = "x".repeat(1024 * 1024); // 1MB
      fs.writeFileSync(logPath, largeContent);

      // Rotate with 500KB limit
      await rotateAuditLog(logPath, 500 * 1024);

      // Original should be rotated to .1
      expect(fs.existsSync(`${logPath}.1`)).toBe(true);
      // Original path should no longer exist (or be empty)
      expect(fs.existsSync(logPath)).toBe(false);
    });

    it("should not rotate when under size limit", async () => {
      const logPath = path.join(tempDir, "audit.jsonl");

      fs.writeFileSync(logPath, "small content");

      await rotateAuditLog(logPath, 1024 * 1024); // 1MB limit

      // Should not have created rotation files
      expect(fs.existsSync(`${logPath}.1`)).toBe(false);
      expect(fs.existsSync(logPath)).toBe(true);
    });
  });

  describe("old log cleanup", () => {
    it("should clean logs older than retention period", async () => {
      const logPath = path.join(tempDir, "audit.jsonl");

      // Create current log
      fs.writeFileSync(logPath, "current");

      // Create old log
      const oldLogPath = `${logPath}.old`;
      fs.writeFileSync(oldLogPath, "old");

      // Set old modification time
      const oldTime = Date.now() - 100 * 24 * 60 * 60 * 1000; // 100 days ago
      fs.utimesSync(oldLogPath, new Date(oldTime), new Date(oldTime));

      const deleted = await cleanOldAuditLogs(logPath, 30); // 30 day retention

      expect(deleted).toBe(1);
      expect(fs.existsSync(oldLogPath)).toBe(false);
      expect(fs.existsSync(logPath)).toBe(true);
    });
  });

  describe("integration with verify flow", () => {
    it("should log verification_pass event on success", () => {
      const plugin = createSafePlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();

      const config = createPermissiveConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { auditLogger });

      verifyPluginSecurity(ctx);

      expect(auditLogger.events.length).toBeGreaterThan(0);
      const passEvent = auditLogger.events.find((e) => e.eventType === "verification_pass");
      expect(passEvent).toBeDefined();
      expect(passEvent!.pluginId).toBe(plugin.manifest.id);
      expect(passEvent!.result).toBe("allow");
    });

    it("should log verification_fail event on hash mismatch", () => {
      const plugin = createTamperedPlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();

      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { auditLogger });

      verifyPluginSecurity(ctx);

      const failEvent = auditLogger.events.find((e) => e.eventType === "verification_fail");
      expect(failEvent).toBeDefined();
      expect(failEvent!.result).toBe("block");
    });

    it("should log hash_mismatch event on tampered content", () => {
      const plugin = createTamperedPlugin(tempDir);
      const auditLogger = createCapturingAuditLogger();

      const config = createStrictConfig({ enableScanning: false });
      const ctx = createVerifyContext(plugin, config, { auditLogger });

      verifyPluginSecurity(ctx);

      const hashEvent = auditLogger.events.find((e) => e.eventType === "hash_mismatch");
      expect(hashEvent).toBeDefined();
      expect(hashEvent!.details.expectedHash).toBeDefined();
      expect(hashEvent!.details.actualHash).toBeDefined();
    });

    it("should log trust_decision for bundled plugins", () => {
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
      expect(trustEvent!.details.reason).toContain("bundled");
    });
  });

  describe("reading audit logs", () => {
    it("should read JSONL audit log", async () => {
      const logPath = path.join(tempDir, "audit.jsonl");
      const config: AuditConfig = {
        enabled: true,
        path: logPath,
        format: "jsonl",
      };

      const logger = createAuditLogger(config);

      logger.log({
        eventType: "verification_pass",
        pluginId: "test-1",
        source: "/1",
        origin: "workspace",
        result: "allow",
        details: {},
      });

      logger.log({
        eventType: "verification_fail",
        pluginId: "test-2",
        source: "/2",
        origin: "global",
        result: "block",
        details: {},
      });

      await logger.flush();

      const events = await readAuditLog(logPath);

      expect(events).toHaveLength(2);
      expect(events[0].pluginId).toBe("test-1");
      expect(events[1].pluginId).toBe("test-2");
    });

    it("should return empty array for non-existent log", async () => {
      const events = await readAuditLog("/non/existent/path.jsonl");
      expect(events).toEqual([]);
    });
  });

  describe("buffer flushing", () => {
    it("should auto-flush when buffer is full", async () => {
      const logPath = path.join(tempDir, "audit.jsonl");
      const config: AuditConfig = {
        enabled: true,
        path: logPath,
        format: "jsonl",
      };

      const logger = createAuditLogger(config);

      // Log more than buffer size (100)
      for (let i = 0; i < 150; i++) {
        logger.log({
          eventType: "load_attempt",
          pluginId: `plugin-${i}`,
          source: `/path/${i}`,
          origin: "workspace",
          result: "allow",
          details: {},
        });
      }

      // File should exist even without explicit flush (auto-flushed at 100)
      expect(fs.existsSync(logPath)).toBe(true);

      // Flush remaining
      await logger.flush();

      const events = await readAuditLog(logPath);
      expect(events).toHaveLength(150);
    });
  });
});
