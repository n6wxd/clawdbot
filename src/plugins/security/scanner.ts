/**
 * Plugin Static Analysis Scanner
 *
 * Pattern-based security scanning for detecting malicious plugin behavior.
 * Ported from skill-guardian with adaptations for OpenClaw.
 */

import fs from "node:fs";
import path from "node:path";

import type { SecurityFinding, SecurityPattern, SecuritySeverity } from "./types.js";

// Import patterns at build time
import patternsData from "./patterns.json" with { type: "json" };

// =============================================================================
// Pattern Loading
// =============================================================================

const loadedPatterns: SecurityPattern[] = patternsData.patterns as SecurityPattern[];

/**
 * Get all loaded security patterns.
 */
export function getSecurityPatterns(): SecurityPattern[] {
  return loadedPatterns;
}

/**
 * Get patterns by severity.
 */
export function getPatternsBySeverity(severity: SecuritySeverity): SecurityPattern[] {
  return loadedPatterns.filter((p) => p.severity === severity);
}

// =============================================================================
// Source Scanning
// =============================================================================

/**
 * Scan source code for security patterns.
 */
export function scanSource(
  source: string,
  options?: { filename?: string; stripComments?: boolean },
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const filename = options?.filename ?? "source";

  // Optionally strip comments to reduce false positives
  const codeToScan = options?.stripComments !== false ? stripJsComments(source) : source;

  const lines = codeToScan.split("\n");

  for (const pattern of loadedPatterns) {
    for (const regexStr of pattern.patterns) {
      try {
        const regex = new RegExp(regexStr, "gi");

        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
          const line = lines[lineNum];
          const matches = line.match(regex);

          if (matches) {
            for (const match of matches) {
              findings.push({
                id: pattern.id,
                severity: pattern.severity,
                file: filename,
                line: lineNum + 1,
                match: match.slice(0, 100), // Truncate long matches
                message: pattern.description,
                context: getContextLines(lines, lineNum, 2),
              });
            }
          }
        }
      } catch {
        // Invalid regex pattern - skip
      }
    }
  }

  return deduplicateFindings(findings);
}

/**
 * Scan a file for security patterns.
 */
export function scanFile(filePath: string): SecurityFinding[] {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const ext = path.extname(filePath);

  // Only strip comments for JS/TS files
  const stripComments = [".js", ".ts", ".mjs", ".cjs", ".mts", ".cts"].includes(ext);

  return scanSource(content, {
    filename: filePath,
    stripComments,
  });
}

/**
 * Scan a directory for security patterns.
 */
export function scanDirectory(
  dirPath: string,
  options?: { extensions?: string[]; exclude?: string[] },
): SecurityFinding[] {
  const extensions = options?.extensions ?? [".js", ".ts", ".mjs", ".cjs", ".mts", ".cts", ".json"];
  const exclude = options?.exclude ?? ["node_modules", ".git", "__tests__", "dist"];

  const findings: SecurityFinding[] = [];

  function walk(currentPath: string): void {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      // Check exclusions
      if (exclude.some((e) => entry.name === e || fullPath.includes(e))) {
        continue;
      }

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (extensions.includes(ext)) {
          findings.push(...scanFile(fullPath));
        }
      }
    }
  }

  if (fs.existsSync(dirPath)) {
    walk(dirPath);
  }

  return findings;
}

// =============================================================================
// Comment Stripping
// =============================================================================

/**
 * Strip JavaScript/TypeScript comments from source code.
 * Preserves line numbers by replacing comments with whitespace.
 */
function stripJsComments(source: string): string {
  let result = "";
  let i = 0;
  let inString: string | null = null;
  let inTemplate = false;
  let templateDepth = 0;

  while (i < source.length) {
    const char = source[i];
    const next = source[i + 1];

    // Handle strings
    if (!inString && !inTemplate) {
      if (char === '"' || char === "'" || char === "`") {
        inString = char;
        if (char === "`") {
          inTemplate = true;
          templateDepth = 1;
        }
        result += char;
        i++;
        continue;
      }
    } else if (inString) {
      if (char === "\\" && i + 1 < source.length) {
        result += char + next;
        i += 2;
        continue;
      }
      if (char === inString && !inTemplate) {
        inString = null;
        result += char;
        i++;
        continue;
      }
      if (inTemplate) {
        if (char === "`") {
          templateDepth--;
          if (templateDepth === 0) {
            inString = null;
            inTemplate = false;
          }
        } else if (char === "$" && next === "{") {
          templateDepth++;
        }
      }
      result += char;
      i++;
      continue;
    }

    // Single-line comment
    if (char === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") {
        result += " ";
        i++;
      }
      continue;
    }

    // Multi-line comment
    if (char === "/" && next === "*") {
      result += "  ";
      i += 2;
      while (i < source.length) {
        if (source[i] === "*" && source[i + 1] === "/") {
          result += "  ";
          i += 2;
          break;
        }
        result += source[i] === "\n" ? "\n" : " ";
        i++;
      }
      continue;
    }

    result += char;
    i++;
  }

  return result;
}

// =============================================================================
// Finding Analysis
// =============================================================================

/**
 * Get context lines around a finding.
 */
function getContextLines(lines: string[], lineNum: number, contextSize: number): string[] {
  const start = Math.max(0, lineNum - contextSize);
  const end = Math.min(lines.length, lineNum + contextSize + 1);
  return lines.slice(start, end);
}

/**
 * Deduplicate findings (same pattern, same line).
 */
function deduplicateFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.id}:${f.file}:${f.line}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

/**
 * Group findings by severity.
 */
export function groupFindingsBySeverity(
  findings: SecurityFinding[],
): Record<SecuritySeverity, SecurityFinding[]> {
  const grouped: Record<SecuritySeverity, SecurityFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

/**
 * Calculate risk score from findings.
 */
export function calculateRiskScore(findings: SecurityFinding[]): {
  score: number;
  verdict: "safe" | "caution" | "unsafe";
} {
  let score = 0;

  for (const finding of findings) {
    switch (finding.severity) {
      case "critical":
        score += 25;
        break;
      case "high":
        score += 15;
        break;
      case "medium":
        score += 5;
        break;
      case "low":
        score += 1;
        break;
    }
  }

  // Cap at 100
  score = Math.min(100, score);

  let verdict: "safe" | "caution" | "unsafe";
  if (score < 30) {
    verdict = "safe";
  } else if (score < 70) {
    verdict = "caution";
  } else {
    verdict = "unsafe";
  }

  return { score, verdict };
}

/**
 * Get highest severity from findings.
 */
export function getHighestSeverity(findings: SecurityFinding[]): SecuritySeverity | "none" {
  const order: SecuritySeverity[] = ["critical", "high", "medium", "low"];

  for (const severity of order) {
    if (findings.some((f) => f.severity === severity)) {
      return severity;
    }
  }

  return "none";
}

/**
 * Format findings as human-readable report.
 */
export function formatFindingsReport(findings: SecurityFinding[]): string {
  if (findings.length === 0) {
    return "No security findings detected.";
  }

  const grouped = groupFindingsBySeverity(findings);
  const { score, verdict } = calculateRiskScore(findings);

  const lines: string[] = [
    `Security Scan Results`,
    `====================`,
    ``,
    `Risk Score: ${score}/100 (${verdict.toUpperCase()})`,
    `Total Findings: ${findings.length}`,
    ``,
  ];

  for (const severity of ["critical", "high", "medium", "low"] as SecuritySeverity[]) {
    const severityFindings = grouped[severity];
    if (severityFindings.length > 0) {
      lines.push(`${severity.toUpperCase()} (${severityFindings.length}):`);
      for (const finding of severityFindings) {
        lines.push(`  [${finding.id}] ${finding.file}:${finding.line}`);
        lines.push(`    ${finding.message}`);
        if (finding.match) {
          lines.push(`    Match: ${finding.match}`);
        }
      }
      lines.push(``);
    }
  }

  return lines.join("\n");
}
