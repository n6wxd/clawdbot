/**
 * Plugin Security Benchmark
 *
 * Performance benchmarking for plugin security verification.
 * Measures individual check times and overall verification overhead.
 */

import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { computeDirectoryHash, computeFileHash } from "./hash.js";
import { generateKeyPair, signManifest, verifyManifestSignature } from "./signature.js";
import { scanDirectory, scanFile } from "./scanner.js";
import { verifyPluginSecurity, normalizeSecurityConfig } from "./verify.js";
import type { PluginSecurityConfig, VerifyContext } from "./types.js";

// =============================================================================
// Types
// =============================================================================

export type BenchmarkResult = {
  name: string;
  iterations: number;
  times: number[];
  stats: {
    min: number;
    max: number;
    mean: number;
    median: number;
    p95: number;
    p99: number;
    stdDev: number;
  };
};

export type BenchmarkSuite = {
  timestamp: string;
  nodeVersion: string;
  platform: string;
  iterations: number;
  results: Record<string, BenchmarkResult>;
  summary: {
    totalTime: number;
    memoryUsageMB: number;
  };
};

export type BenchmarkOptions = {
  iterations?: number;
  warmupIterations?: number;
  pluginPath?: string;
  outputPath?: string;
  verbose?: boolean;
};

// =============================================================================
// Benchmark Runner
// =============================================================================

/**
 * Run full benchmark suite.
 */
export async function runBenchmarkSuite(options: BenchmarkOptions = {}): Promise<BenchmarkSuite> {
  const iterations = options.iterations ?? 100;
  const warmupIterations = options.warmupIterations ?? 10;
  const verbose = options.verbose ?? false;

  const log = verbose ? console.log : () => {};

  log(`\nPlugin Security Benchmark Suite`);
  log(`================================`);
  log(`Iterations: ${iterations}`);
  log(`Warmup: ${warmupIterations}`);
  log(``);

  const startTime = performance.now();
  const startMemory = process.memoryUsage();

  const results: Record<string, BenchmarkResult> = {};

  // Create test fixtures
  const fixtures = await createTestFixtures();

  // Benchmark: Hash computation
  log(`Benchmarking hash computation...`);
  results.hashFile = await benchmarkHashFile(fixtures.filePath, iterations, warmupIterations);

  log(`Benchmarking directory hash...`);
  results.hashDirectory = await benchmarkHashDirectory(fixtures.dirPath, iterations, warmupIterations);

  // Benchmark: Signature operations
  log(`Benchmarking key generation...`);
  results.keyGeneration = await benchmarkKeyGeneration(iterations, warmupIterations);

  log(`Benchmarking signature creation...`);
  results.signManifest = await benchmarkSignManifest(fixtures.manifest, iterations, warmupIterations);

  log(`Benchmarking signature verification...`);
  results.verifySignature = await benchmarkVerifySignature(
    fixtures.signedManifest,
    fixtures.publicKey,
    iterations,
    warmupIterations,
  );

  // Benchmark: Static analysis
  log(`Benchmarking file scan...`);
  results.scanFile = await benchmarkScanFile(fixtures.filePath, iterations, warmupIterations);

  log(`Benchmarking directory scan...`);
  results.scanDirectory = await benchmarkScanDirectory(fixtures.dirPath, iterations, warmupIterations);

  // Benchmark: Full verification
  log(`Benchmarking full verification (no security)...`);
  results.verifyOff = await benchmarkFullVerification(
    fixtures,
    { mode: "off" },
    iterations,
    warmupIterations,
  );

  log(`Benchmarking full verification (permissive)...`);
  results.verifyPermissive = await benchmarkFullVerification(
    fixtures,
    { mode: "permissive" },
    iterations,
    warmupIterations,
  );

  log(`Benchmarking full verification (strict)...`);
  results.verifyStrict = await benchmarkFullVerification(
    fixtures,
    { mode: "strict", enableScanning: true },
    iterations,
    warmupIterations,
  );

  // Cleanup
  await cleanupTestFixtures(fixtures);

  const endTime = performance.now();
  const endMemory = process.memoryUsage();

  const suite: BenchmarkSuite = {
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    iterations,
    results,
    summary: {
      totalTime: endTime - startTime,
      memoryUsageMB: (endMemory.heapUsed - startMemory.heapUsed) / 1024 / 1024,
    },
  };

  if (options.outputPath) {
    fs.writeFileSync(options.outputPath, JSON.stringify(suite, null, 2));
    log(`\nResults written to: ${options.outputPath}`);
  }

  return suite;
}

// =============================================================================
// Individual Benchmarks
// =============================================================================

async function benchmarkHashFile(
  filePath: string,
  iterations: number,
  warmup: number,
): Promise<BenchmarkResult> {
  // Warmup
  for (let i = 0; i < warmup; i++) {
    computeFileHash(filePath);
  }

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    computeFileHash(filePath);
    times.push(performance.now() - start);
  }

  return { name: "hashFile", iterations, times, stats: calculateStats(times) };
}

async function benchmarkHashDirectory(
  dirPath: string,
  iterations: number,
  warmup: number,
): Promise<BenchmarkResult> {
  for (let i = 0; i < warmup; i++) {
    computeDirectoryHash(dirPath);
  }

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    computeDirectoryHash(dirPath);
    times.push(performance.now() - start);
  }

  return { name: "hashDirectory", iterations, times, stats: calculateStats(times) };
}

async function benchmarkKeyGeneration(
  iterations: number,
  warmup: number,
): Promise<BenchmarkResult> {
  for (let i = 0; i < warmup; i++) {
    generateKeyPair();
  }

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    generateKeyPair();
    times.push(performance.now() - start);
  }

  return { name: "keyGeneration", iterations, times, stats: calculateStats(times) };
}

async function benchmarkSignManifest(
  manifest: TestManifest,
  iterations: number,
  warmup: number,
): Promise<BenchmarkResult> {
  const { privateKey } = generateKeyPair();

  for (let i = 0; i < warmup; i++) {
    signManifest(manifest, privateKey);
  }

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    signManifest(manifest, privateKey);
    times.push(performance.now() - start);
  }

  return { name: "signManifest", iterations, times, stats: calculateStats(times) };
}

async function benchmarkVerifySignature(
  manifest: TestManifest,
  publicKey: string,
  iterations: number,
  warmup: number,
): Promise<BenchmarkResult> {
  for (let i = 0; i < warmup; i++) {
    verifyManifestSignature(manifest, publicKey);
  }

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    verifyManifestSignature(manifest, publicKey);
    times.push(performance.now() - start);
  }

  return { name: "verifySignature", iterations, times, stats: calculateStats(times) };
}

async function benchmarkScanFile(
  filePath: string,
  iterations: number,
  warmup: number,
): Promise<BenchmarkResult> {
  for (let i = 0; i < warmup; i++) {
    scanFile(filePath);
  }

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    scanFile(filePath);
    times.push(performance.now() - start);
  }

  return { name: "scanFile", iterations, times, stats: calculateStats(times) };
}

async function benchmarkScanDirectory(
  dirPath: string,
  iterations: number,
  warmup: number,
): Promise<BenchmarkResult> {
  for (let i = 0; i < warmup; i++) {
    scanDirectory(dirPath);
  }

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    scanDirectory(dirPath);
    times.push(performance.now() - start);
  }

  return { name: "scanDirectory", iterations, times, stats: calculateStats(times) };
}

async function benchmarkFullVerification(
  fixtures: TestFixtures,
  configOverrides: Partial<PluginSecurityConfig>,
  iterations: number,
  warmup: number,
): Promise<BenchmarkResult> {
  const config = normalizeSecurityConfig({
    ...configOverrides,
    trustedKeys: [{ id: "test", publicKey: fixtures.publicKey }],
  });

  const ctx: VerifyContext = {
    pluginId: "benchmark-plugin",
    source: fixtures.manifestPath,
    origin: "global",
    manifest: fixtures.signedManifest,
    config,
  };

  for (let i = 0; i < warmup; i++) {
    verifyPluginSecurity(ctx);
  }

  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    verifyPluginSecurity(ctx);
    times.push(performance.now() - start);
  }

  const name = `verify_${configOverrides.mode ?? "default"}`;
  return { name, iterations, times, stats: calculateStats(times) };
}

// =============================================================================
// Statistics
// =============================================================================

function calculateStats(times: number[]): BenchmarkResult["stats"] {
  const sorted = [...times].sort((a, b) => a - b);
  const n = sorted.length;

  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / n;

  const squaredDiffs = sorted.map((t) => Math.pow(t - mean, 2));
  const variance = squaredDiffs.reduce((a, b) => a + b, 0) / n;
  const stdDev = Math.sqrt(variance);

  return {
    min: sorted[0],
    max: sorted[n - 1],
    mean,
    median: sorted[Math.floor(n / 2)],
    p95: sorted[Math.floor(n * 0.95)],
    p99: sorted[Math.floor(n * 0.99)],
    stdDev,
  };
}

// =============================================================================
// Test Fixtures
// =============================================================================

type TestManifest = {
  id: string;
  version?: string;
  security?: {
    contentHash?: string;
    signature?: string;
    signedBy?: string;
  };
};

type TestFixtures = {
  tempDir: string;
  dirPath: string;
  filePath: string;
  manifestPath: string;
  manifest: TestManifest;
  signedManifest: TestManifest;
  publicKey: string;
  privateKey: string;
};

async function createTestFixtures(): Promise<TestFixtures> {
  const os = await import("node:os");
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-benchmark-"));

  // Create a realistic plugin structure
  const pluginDir = path.join(tempDir, "test-plugin");
  fs.mkdirSync(pluginDir, { recursive: true });

  // Create source file with typical plugin code
  const sourceCode = `
// Test plugin for benchmarking
export function register(api) {
  api.registerTool({
    name: 'benchmark-tool',
    description: 'A tool for benchmarking',
    parameters: {
      input: { type: 'string', description: 'Input value' }
    },
    execute: async ({ input }) => {
      return { result: input.toUpperCase() };
    }
  });
}

export const metadata = {
  name: 'Benchmark Plugin',
  version: '1.0.0',
  author: 'Test'
};
`.repeat(10); // Make it a reasonable size

  const indexPath = path.join(pluginDir, "index.js");
  fs.writeFileSync(indexPath, sourceCode);

  // Create additional files
  fs.writeFileSync(
    path.join(pluginDir, "utils.js"),
    `export const helper = (x) => x * 2;\n`.repeat(50),
  );
  fs.writeFileSync(
    path.join(pluginDir, "config.json"),
    JSON.stringify({ setting1: true, setting2: "value" }),
  );

  // Create manifest
  const contentHash = computeFileHash(indexPath).formatted;
  const manifest: TestManifest = {
    id: "benchmark-plugin",
    version: "1.0.0",
    security: {
      contentHash,
    },
  };

  const manifestPath = path.join(pluginDir, "openclaw.plugin.json");
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  // Generate keys and sign
  const { publicKey, privateKey } = generateKeyPair();
  const signature = signManifest(manifest, privateKey);

  const signedManifest: TestManifest = {
    ...manifest,
    security: {
      ...manifest.security,
      signature,
      signedBy: "test",
    },
  };

  return {
    tempDir,
    dirPath: pluginDir,
    filePath: indexPath,
    manifestPath,
    manifest,
    signedManifest,
    publicKey,
    privateKey,
  };
}

async function cleanupTestFixtures(fixtures: TestFixtures): Promise<void> {
  fs.rmSync(fixtures.tempDir, { recursive: true, force: true });
}

// =============================================================================
// Report Generation
// =============================================================================

/**
 * Format benchmark results as a human-readable report.
 */
export function formatBenchmarkReport(suite: BenchmarkSuite): string {
  const lines: string[] = [
    `Plugin Security Benchmark Report`,
    `================================`,
    ``,
    `Timestamp: ${suite.timestamp}`,
    `Node: ${suite.nodeVersion}`,
    `Platform: ${suite.platform}`,
    `Iterations: ${suite.iterations}`,
    ``,
    `Results (times in milliseconds):`,
    ``,
    `${"Operation".padEnd(25)} ${"Min".padStart(8)} ${"Mean".padStart(8)} ${"Median".padStart(8)} ${"P95".padStart(8)} ${"P99".padStart(8)} ${"Max".padStart(8)}`,
    `${"-".repeat(25)} ${"-".repeat(8)} ${"-".repeat(8)} ${"-".repeat(8)} ${"-".repeat(8)} ${"-".repeat(8)} ${"-".repeat(8)}`,
  ];

  for (const [name, result] of Object.entries(suite.results)) {
    const s = result.stats;
    lines.push(
      `${name.padEnd(25)} ${fmt(s.min)} ${fmt(s.mean)} ${fmt(s.median)} ${fmt(s.p95)} ${fmt(s.p99)} ${fmt(s.max)}`,
    );
  }

  lines.push(``);
  lines.push(`Summary:`);
  lines.push(`  Total benchmark time: ${(suite.summary.totalTime / 1000).toFixed(2)}s`);
  lines.push(`  Memory delta: ${suite.summary.memoryUsageMB.toFixed(2)} MB`);
  lines.push(``);

  // Calculate overhead
  const verifyOff = suite.results.verifyOff?.stats.mean ?? 0;
  const verifyPermissive = suite.results.verifyPermissive?.stats.mean ?? 0;
  const verifyStrict = suite.results.verifyStrict?.stats.mean ?? 0;

  lines.push(`Security Overhead:`);
  lines.push(`  Permissive mode: +${(verifyPermissive - verifyOff).toFixed(3)}ms (+${pct(verifyOff, verifyPermissive)})`);
  lines.push(`  Strict mode: +${(verifyStrict - verifyOff).toFixed(3)}ms (+${pct(verifyOff, verifyStrict)})`);

  return lines.join("\n");
}

function fmt(n: number): string {
  return n.toFixed(3).padStart(8);
}

function pct(base: number, value: number): string {
  if (base === 0) return "N/A";
  return `${(((value - base) / base) * 100).toFixed(1)}%`;
}

// =============================================================================
// CLI Entry Point
// =============================================================================

/**
 * Run benchmarks from command line.
 */
export async function runBenchmarkCli(): Promise<void> {
  const args = process.argv.slice(2);
  const iterations = parseInt(args.find((a) => a.startsWith("--iterations="))?.split("=")[1] ?? "100");
  const outputPath = args.find((a) => a.startsWith("--output="))?.split("=")[1];
  const verbose = args.includes("--verbose") || args.includes("-v");

  console.log(`\nRunning plugin security benchmarks...`);

  const suite = await runBenchmarkSuite({
    iterations,
    outputPath,
    verbose,
  });

  console.log(``);
  console.log(formatBenchmarkReport(suite));
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runBenchmarkCli().catch(console.error);
}
