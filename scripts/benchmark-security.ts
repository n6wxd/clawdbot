#!/usr/bin/env tsx
/**
 * Plugin Security Benchmark Runner
 *
 * Usage:
 *   pnpm tsx scripts/benchmark-security.ts
 *   pnpm tsx scripts/benchmark-security.ts --iterations=200
 *   pnpm tsx scripts/benchmark-security.ts --output=benchmark-results.json
 */

import fs from "node:fs";
import path from "node:path";

import { formatBenchmarkReport, runBenchmarkSuite } from "../src/plugins/security/benchmark.js";

async function main() {
  const args = process.argv.slice(2);

  // Parse arguments
  const iterations = parseInt(
    args.find((a) => a.startsWith("--iterations="))?.split("=")[1] ?? "100",
  );
  const outputArg = args.find((a) => a.startsWith("--output="))?.split("=")[1];
  const verbose = args.includes("--verbose") || args.includes("-v");
  const json = args.includes("--json");

  // Default output path
  const outputPath =
    outputArg ?? path.join(process.cwd(), `benchmark-${Date.now()}.json`);

  console.log(`\n🔒 Plugin Security Benchmark`);
  console.log(`============================\n`);

  const suite = await runBenchmarkSuite({
    iterations,
    outputPath,
    verbose,
  });

  if (json) {
    console.log(JSON.stringify(suite, null, 2));
  } else {
    console.log(formatBenchmarkReport(suite));
  }

  // Print baseline targets
  console.log(`\nBaseline Targets:`);
  console.log(`-----------------`);
  console.log(`Hash file:         < 5ms (actual: ${suite.results.hashFile?.stats.p95.toFixed(3)}ms p95)`);
  console.log(`Hash directory:    < 20ms (actual: ${suite.results.hashDirectory?.stats.p95.toFixed(3)}ms p95)`);
  console.log(`Signature verify:  < 10ms (actual: ${suite.results.verifySignature?.stats.p95.toFixed(3)}ms p95)`);
  console.log(`Scan file:         < 50ms (actual: ${suite.results.scanFile?.stats.p95.toFixed(3)}ms p95)`);
  console.log(`Scan directory:    < 100ms (actual: ${suite.results.scanDirectory?.stats.p95.toFixed(3)}ms p95)`);
  console.log(`Full verify:       < 150ms (actual: ${suite.results.verifyStrict?.stats.p95.toFixed(3)}ms p95)`);

  // Check if any baselines are exceeded
  const issues: string[] = [];
  if ((suite.results.hashFile?.stats.p95 ?? 0) > 5) issues.push("hashFile");
  if ((suite.results.hashDirectory?.stats.p95 ?? 0) > 20) issues.push("hashDirectory");
  if ((suite.results.verifySignature?.stats.p95 ?? 0) > 10) issues.push("verifySignature");
  if ((suite.results.scanFile?.stats.p95 ?? 0) > 50) issues.push("scanFile");
  if ((suite.results.scanDirectory?.stats.p95 ?? 0) > 100) issues.push("scanDirectory");
  if ((suite.results.verifyStrict?.stats.p95 ?? 0) > 150) issues.push("verifyStrict");

  if (issues.length > 0) {
    console.log(`\n⚠️  Performance regression detected in: ${issues.join(", ")}`);
    process.exit(1);
  } else {
    console.log(`\n✅ All benchmarks within baseline targets`);
  }

  console.log(`\nResults saved to: ${outputPath}`);
}

main().catch((err) => {
  console.error("Benchmark failed:", err);
  process.exit(1);
});
