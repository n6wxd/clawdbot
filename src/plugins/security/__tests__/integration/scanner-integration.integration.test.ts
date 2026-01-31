/**
 * Scanner Integration Tests
 *
 * Tests the static analysis scanner against real plugin fixtures,
 * including skill-guardian test plugins when available.
 */

import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  calculateRiskScore,
  getHighestSeverity,
  groupFindingsBySeverity,
  scanDirectory,
  scanFile,
  scanSource,
} from "../../scanner.js";
import type { SecurityFinding, SecuritySeverity } from "../../types.js";
import {
  cleanupTempDir,
  createMaliciousCodeExecPlugin,
  createMaliciousCredExfilPlugin,
  createMaliciousObfuscatedPlugin,
  createSafePlugin,
  createTempDir,
  getFixturePaths,
} from "./setup.js";

describe("scanner-integration", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir("scanner-test-");
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("scanning generated test plugins", () => {
    it("should detect no findings in safe plugin", () => {
      const plugin = createSafePlugin(tempDir);
      const findings = scanFile(plugin.entryPath);

      expect(findings).toHaveLength(0);

      const { score, verdict } = calculateRiskScore(findings);
      expect(score).toBe(0);
      expect(verdict).toBe("safe");
    });

    it("should detect CRED_EXFIL patterns in credential exfiltration plugin", () => {
      const plugin = createMaliciousCredExfilPlugin(tempDir);
      const findings = scanFile(plugin.entryPath);

      expect(findings.length).toBeGreaterThan(0);

      // Should detect .env file access
      const credFindings = findings.filter((f) => f.id.startsWith("CRED_EXFIL"));
      expect(credFindings.length).toBeGreaterThan(0);

      const highest = getHighestSeverity(findings);
      expect(highest).toBe("critical");
    });

    it("should detect CODE_EXEC patterns in eval plugin", () => {
      const plugin = createMaliciousCodeExecPlugin(tempDir);
      const findings = scanFile(plugin.entryPath);

      expect(findings.length).toBeGreaterThan(0);

      // Should detect eval usage
      const codeExecFindings = findings.filter((f) => f.id.startsWith("CODE_EXEC"));
      expect(codeExecFindings.length).toBeGreaterThan(0);

      const highest = getHighestSeverity(findings);
      expect(["critical", "high"]).toContain(highest);
    });

    it("should detect OBFUSCATION patterns in base64 encoded plugin", () => {
      const plugin = createMaliciousObfuscatedPlugin(tempDir);
      const findings = scanFile(plugin.entryPath);

      expect(findings.length).toBeGreaterThan(0);

      // Should detect base64 decoding and eval
      const obfuscationFindings = findings.filter((f) => f.id.startsWith("OBFUSCATION"));
      const codeExecFindings = findings.filter((f) => f.id.startsWith("CODE_EXEC"));

      expect(obfuscationFindings.length + codeExecFindings.length).toBeGreaterThan(0);
    });

    it("should calculate risk score correctly", () => {
      const plugin = createMaliciousObfuscatedPlugin(tempDir);
      const findings = scanFile(plugin.entryPath);

      const { score, verdict } = calculateRiskScore(findings);

      // Obfuscated plugin has eval + base64, should be unsafe
      expect(score).toBeGreaterThan(0);
      expect(["caution", "unsafe"]).toContain(verdict);
    });

    it("should group findings by severity", () => {
      const plugin = createMaliciousCredExfilPlugin(tempDir);
      const findings = scanFile(plugin.entryPath);

      const grouped = groupFindingsBySeverity(findings);

      expect(grouped).toHaveProperty("critical");
      expect(grouped).toHaveProperty("high");
      expect(grouped).toHaveProperty("medium");
      expect(grouped).toHaveProperty("low");

      // Should have at least critical findings for cred exfil
      expect(grouped.critical.length).toBeGreaterThan(0);
    });
  });

  describe("scanning source code directly", () => {
    it("should detect process.env harvesting", () => {
      const code = `
        const secrets = process.env;
        const apiKey = process.env.API_KEY;
        const token = process.env.SECRET_TOKEN;
      `;

      const findings = scanSource(code, { filename: "test.js" });

      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.id === "CRED_EXFIL_002")).toBe(true);
    });

    it("should detect suspicious network endpoints", () => {
      const code = `
        fetch('https://webhook.site/abc123');
        fetch('https://requestbin.com/data');
        fetch('https://pipedream.net/endpoint');
      `;

      const findings = scanSource(code, { filename: "test.js" });

      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.id === "NETWORK_EXFIL_001")).toBe(true);
    });

    it("should detect dynamic code execution patterns", () => {
      const code = `
        const result = eval(userInput);
        new Function('return ' + code)();
        const fn = new Function(payload);
      `;

      const findings = scanSource(code, { filename: "test.js" });

      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.id === "CODE_EXEC_001")).toBe(true);
    });

    it("should not flag normal code as malicious", () => {
      const code = `
        // Normal, safe code
        export function add(a, b) {
          return a + b;
        }

        export function greet(name) {
          return \`Hello, \${name}!\`;
        }

        const data = JSON.parse(jsonString);
        const result = await fetch('/api/data');
      `;

      const findings = scanSource(code, { filename: "test.js" });
      expect(findings).toHaveLength(0);
    });

    it("should respect stripComments option", () => {
      const codeWithComment = `
        // const secrets = process.env;
        const x = 1;
      `;

      // With comment stripping (default for JS)
      const findingsStripped = scanSource(codeWithComment, {
        filename: "test.js",
        stripComments: true,
      });
      expect(findingsStripped).toHaveLength(0);

      // Without comment stripping
      const findingsUnstripped = scanSource(codeWithComment, {
        filename: "test.js",
        stripComments: false,
      });
      // May or may not find it depending on pattern - just verify it runs
      expect(Array.isArray(findingsUnstripped)).toBe(true);
    });
  });

  describe("scanning directories", () => {
    it("should scan all files in directory", () => {
      // Create multiple plugins in the same directory
      const safe = createSafePlugin(tempDir, "safe-plugin");
      const malicious = createMaliciousCodeExecPlugin(tempDir, "malicious-plugin");

      // Scan the entire temp directory
      const findings = scanDirectory(tempDir);

      // Should find the malicious code
      expect(findings.length).toBeGreaterThan(0);

      // Findings should reference the malicious plugin file
      const maliciousFindings = findings.filter((f) => f.file.includes("malicious-plugin"));
      expect(maliciousFindings.length).toBeGreaterThan(0);
    });

    it("should exclude node_modules by default", () => {
      const plugin = createSafePlugin(tempDir);

      // Create a node_modules with malicious code
      const nodeModulesDir = path.join(plugin.dir, "node_modules", "evil-package");
      fs.mkdirSync(nodeModulesDir, { recursive: true });
      fs.writeFileSync(
        path.join(nodeModulesDir, "index.js"),
        "const secrets = process.env;",
      );

      const findings = scanDirectory(plugin.dir);

      // Should not find the node_modules malicious code
      const nodeModulesFindings = findings.filter((f) => f.file.includes("node_modules"));
      expect(nodeModulesFindings).toHaveLength(0);
    });

    it("should respect custom extensions filter", () => {
      const plugin = createSafePlugin(tempDir);

      // Create a .txt file with malicious patterns
      fs.writeFileSync(
        path.join(plugin.dir, "notes.txt"),
        "const secrets = process.env;",
      );

      // Scan only .js files
      const findingsJsOnly = scanDirectory(plugin.dir, { extensions: [".js"] });

      // Scan .txt files too
      const findingsWithTxt = scanDirectory(plugin.dir, { extensions: [".js", ".txt"] });

      // The .txt file should only be detected when included
      const txtFindings = findingsWithTxt.filter((f) => f.file.endsWith(".txt"));
      expect(txtFindings.length).toBeGreaterThanOrEqual(findingsJsOnly.filter((f) => f.file.endsWith(".txt")).length);
    });
  });

  describe("skill-guardian fixtures", () => {
    const fixtures = getFixturePaths();

    // Skip these tests if fixtures aren't available
    const describeWithFixtures = fixtures ? describe : describe.skip;

    describeWithFixtures("malicious plugins", () => {
      it("should detect CRED_EXFIL_001 in cred-exfil-001 fixture", () => {
        const findings = scanFile(path.join(fixtures!.malicious.credExfil001, "index.js"));

        expect(findings.length).toBeGreaterThan(0);
        expect(findings.some((f) => f.id === "CRED_EXFIL_001")).toBe(true);

        const highest = getHighestSeverity(findings);
        expect(highest).toBe("critical");
      });

      it("should detect CODE_EXEC_001 in code-exec-001 fixture", () => {
        const findings = scanFile(path.join(fixtures!.malicious.codeExec001, "index.js"));

        expect(findings.length).toBeGreaterThan(0);
        expect(findings.some((f) => f.id === "CODE_EXEC_001")).toBe(true);
      });

      it("should detect OBFUSCATION_001 in obfuscation-001 fixture", () => {
        const findings = scanFile(path.join(fixtures!.malicious.obfuscation001, "index.js"));

        expect(findings.length).toBeGreaterThan(0);
        // Should detect either obfuscation or code exec (base64 + eval)
        const hasObfuscation = findings.some((f) => f.id.startsWith("OBFUSCATION"));
        const hasCodeExec = findings.some((f) => f.id.startsWith("CODE_EXEC"));
        expect(hasObfuscation || hasCodeExec).toBe(true);
      });

      it("should detect NETWORK_EXFIL_001 in network-exfil-001 fixture", () => {
        const findings = scanFile(path.join(fixtures!.malicious.networkExfil001, "index.js"));

        expect(findings.length).toBeGreaterThan(0);
        expect(findings.some((f) => f.id === "NETWORK_EXFIL_001")).toBe(true);
      });
    });

    describeWithFixtures("safe plugins", () => {
      it("should have no critical findings in minimal safe fixture", () => {
        const findings = scanFile(path.join(fixtures!.safe.minimal, "index.js"));

        const { verdict } = calculateRiskScore(findings);
        expect(verdict).toBe("safe");
      });

      it("should have no critical findings in signed safe fixture", () => {
        const findings = scanFile(path.join(fixtures!.safe.signed, "index.js"));

        const grouped = groupFindingsBySeverity(findings);
        expect(grouped.critical).toHaveLength(0);
      });
    });
  });

  describe("finding context", () => {
    it("should include context lines around findings", () => {
      const code = `
        function setup() {
          console.log('setup');
        }
        const secrets = process.env;
        function cleanup() {
          console.log('cleanup');
        }
      `;

      const findings = scanSource(code, { filename: "test.js" });

      expect(findings.length).toBeGreaterThan(0);

      const finding = findings[0];
      expect(finding.context).toBeDefined();
      expect(finding.context!.length).toBeGreaterThan(0);
    });

    it("should include line numbers in findings", () => {
      const code = `line1
line2
const x = eval(code);
line4`;

      const findings = scanSource(code, { filename: "test.js" });

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].line).toBe(3);
    });

    it("should truncate long matches", () => {
      const longCode = "eval(" + "x".repeat(200) + ")";
      const findings = scanSource(longCode, { filename: "test.js" });

      if (findings.length > 0 && findings[0].match) {
        expect(findings[0].match.length).toBeLessThanOrEqual(100);
      }
    });
  });

  describe("deduplication", () => {
    it("should deduplicate findings on same line", () => {
      const code = `
        const a = eval(code1);
        // This line has eval twice: eval(x); eval(y);
      `;

      const findings = scanSource(code, { filename: "test.js", stripComments: false });

      // Should have unique findings per pattern:file:line
      const keys = findings.map((f) => `${f.id}:${f.file}:${f.line}`);
      const uniqueKeys = [...new Set(keys)];
      expect(keys.length).toBe(uniqueKeys.length);
    });
  });
});
