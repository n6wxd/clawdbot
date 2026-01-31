/**
 * Plugin Content Hashing
 *
 * SHA-256 content hashing for plugin integrity verification.
 * Uses only Node.js built-in crypto module.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import type { DirectoryHashOptions, HashAlgorithm, HashResult } from "./types.js";

const DEFAULT_ALGORITHM: HashAlgorithm = "sha256";

const DEFAULT_EXTENSIONS = [".js", ".ts", ".mjs", ".cjs", ".mts", ".cts", ".json"];

const DEFAULT_EXCLUDE = ["node_modules", ".git", "__tests__", "*.test.ts", "*.test.js"];

// =============================================================================
// Content Hashing
// =============================================================================

/**
 * Compute SHA-256 hash of a string or buffer.
 */
export function computeHash(content: string | Buffer): HashResult {
  const hash = createHash(DEFAULT_ALGORITHM).update(content).digest("hex");

  return {
    algorithm: DEFAULT_ALGORITHM,
    hash,
    formatted: `${DEFAULT_ALGORITHM}:${hash}`,
  };
}

/**
 * Compute SHA-256 hash of a file.
 */
export function computeFileHash(filePath: string): HashResult {
  const content = fs.readFileSync(filePath);
  return computeHash(content);
}

/**
 * Result of hash computation that includes the original content.
 * Used for atomic verify-and-use patterns to prevent TOCTOU attacks.
 */
export type HashResultWithContent = HashResult & {
  /** The content that was hashed */
  content: Buffer;
};

/**
 * Compute SHA-256 hash of a file and return both hash and content.
 * This enables atomic verification patterns where the verified content
 * can be used directly without re-reading from disk.
 */
export function computeFileHashWithContent(filePath: string): HashResultWithContent {
  const content = fs.readFileSync(filePath);
  const hashResult = computeHash(content);
  return { ...hashResult, content };
}

/**
 * Result of hash verification that includes content if verification passed.
 */
export type VerifyHashResult = {
  /** Whether the hash matched */
  valid: boolean;
  /** The actual hash computed from the file */
  actualHash: HashResult;
  /** The content, only provided if hash matched (for atomic use) */
  content?: Buffer;
};

/**
 * Verify a file's content hash and return the content if valid.
 * This is the secure alternative to verifyFileHash that prevents TOCTOU attacks
 * by returning the verified content for immediate use.
 */
export function verifyFileHashWithContent(filePath: string, expected: string): VerifyHashResult {
  const { content, ...hashResult } = computeFileHashWithContent(filePath);
  const valid = compareHashes(hashResult.formatted, expected) || compareHashes(hashResult.hash, expected);

  return {
    valid,
    actualHash: hashResult,
    // Only return content if hash matched - prevents returning tampered content
    content: valid ? content : undefined,
  };
}

/**
 * Compute deterministic hash of a directory's contents.
 *
 * Files are sorted alphabetically by relative path to ensure
 * deterministic hashing regardless of filesystem order.
 */
export function computeDirectoryHash(
  dirPath: string,
  options: DirectoryHashOptions = {},
): HashResult {
  const extensions = options.extensions ?? DEFAULT_EXTENSIONS;
  const exclude = options.exclude ?? DEFAULT_EXCLUDE;
  const includeHidden = options.includeHidden ?? false;

  const files = collectFiles(dirPath, extensions, exclude, includeHidden);

  // Sort files for deterministic ordering
  files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));

  // Create combined hash of all file contents
  const hasher = createHash(DEFAULT_ALGORITHM);

  for (const file of files) {
    // Include relative path in hash to detect file renames
    hasher.update(file.relativePath);
    hasher.update(file.content);
  }

  const hash = hasher.digest("hex");

  return {
    algorithm: DEFAULT_ALGORITHM,
    hash,
    formatted: `${DEFAULT_ALGORITHM}:${hash}`,
  };
}

// =============================================================================
// Verification
// =============================================================================

/**
 * Verify a file's content hash matches the expected value.
 */
export function verifyFileHash(filePath: string, expected: string): boolean {
  const actual = computeFileHash(filePath);
  return compareHashes(actual.formatted, expected) || compareHashes(actual.hash, expected);
}

/**
 * Verify a directory's content hash matches the expected value.
 */
export function verifyDirectoryHash(
  dirPath: string,
  expected: string,
  options?: DirectoryHashOptions,
): boolean {
  const actual = computeDirectoryHash(dirPath, options);
  return compareHashes(actual.formatted, expected) || compareHashes(actual.hash, expected);
}

/**
 * Compare two hash values, handling both formatted (algo:hash) and raw formats.
 */
export function compareHashes(actual: string, expected: string): boolean {
  const normalizedActual = normalizeHash(actual);
  const normalizedExpected = normalizeHash(expected);
  return constantTimeCompare(normalizedActual, normalizedExpected);
}

// =============================================================================
// Helpers
// =============================================================================

type FileEntry = {
  relativePath: string;
  content: Buffer;
};

/**
 * Collect all files in a directory matching the criteria.
 */
function collectFiles(
  dirPath: string,
  extensions: string[],
  exclude: string[],
  includeHidden: boolean,
): FileEntry[] {
  const files: FileEntry[] = [];
  const basePath = path.resolve(dirPath);

  function walk(currentPath: string): void {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      const relativePath = path.relative(basePath, fullPath);

      // Skip hidden files unless explicitly included
      if (!includeHidden && entry.name.startsWith(".")) {
        continue;
      }

      // Check exclusion patterns
      if (isExcluded(relativePath, entry.name, exclude)) {
        continue;
      }

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        // Check extension
        const ext = path.extname(entry.name);
        if (extensions.includes(ext)) {
          files.push({
            relativePath,
            content: fs.readFileSync(fullPath),
          });
        }
      }
    }
  }

  walk(basePath);
  return files;
}

/**
 * Check if a path matches any exclusion pattern.
 */
function isExcluded(relativePath: string, name: string, exclude: string[]): boolean {
  for (const pattern of exclude) {
    // Direct name match
    if (name === pattern) {
      return true;
    }

    // Path contains pattern
    if (relativePath.includes(pattern)) {
      return true;
    }

    // Glob-style matching (simple)
    if (pattern.startsWith("*")) {
      const suffix = pattern.slice(1);
      if (name.endsWith(suffix)) {
        return true;
      }
    }

    if (pattern.endsWith("*")) {
      const prefix = pattern.slice(0, -1);
      if (name.startsWith(prefix)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Normalize hash to raw hex format (strip algorithm prefix if present).
 */
function normalizeHash(hash: string): string {
  // Handle "sha256:abc123..." format
  const colonIndex = hash.indexOf(":");
  if (colonIndex !== -1) {
    return hash.slice(colonIndex + 1).toLowerCase();
  }
  return hash.toLowerCase();
}

/**
 * Constant-time string comparison to prevent timing attacks.
 */
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

// =============================================================================
// Utilities
// =============================================================================

/**
 * Format a hash value with algorithm prefix.
 */
export function formatHash(hash: string, algorithm: HashAlgorithm = DEFAULT_ALGORITHM): string {
  // Already formatted
  if (hash.includes(":")) {
    return hash;
  }
  return `${algorithm}:${hash}`;
}

/**
 * Parse a formatted hash string.
 */
export function parseHash(formatted: string): { algorithm: string; hash: string } {
  const colonIndex = formatted.indexOf(":");
  if (colonIndex === -1) {
    return { algorithm: DEFAULT_ALGORITHM, hash: formatted };
  }
  return {
    algorithm: formatted.slice(0, colonIndex),
    hash: formatted.slice(colonIndex + 1),
  };
}

/**
 * Validate hash format.
 */
export function isValidHash(hash: string): boolean {
  const { hash: rawHash } = parseHash(hash);
  // SHA-256 produces 64 hex characters
  return /^[a-f0-9]{64}$/i.test(rawHash);
}
