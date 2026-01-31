import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  compareHashes,
  computeDirectoryHash,
  computeFileHash,
  computeHash,
  formatHash,
  isValidHash,
  parseHash,
  verifyDirectoryHash,
  verifyFileHash,
} from "../hash.js";

describe("hash", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hash-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe("computeHash", () => {
    it("should compute SHA-256 hash of string content", () => {
      const result = computeHash("hello world");

      expect(result.algorithm).toBe("sha256");
      expect(result.hash).toBe("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
      expect(result.formatted).toBe(
        "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      );
    });

    it("should compute SHA-256 hash of buffer content", () => {
      const buffer = Buffer.from("hello world");
      const result = computeHash(buffer);

      expect(result.hash).toBe("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    });

    it("should produce different hashes for different content", () => {
      const hash1 = computeHash("content 1");
      const hash2 = computeHash("content 2");

      expect(hash1.hash).not.toBe(hash2.hash);
    });

    it("should produce consistent hashes for same content", () => {
      const hash1 = computeHash("test content");
      const hash2 = computeHash("test content");

      expect(hash1.hash).toBe(hash2.hash);
    });
  });

  describe("computeFileHash", () => {
    it("should compute hash of file contents", () => {
      const filePath = path.join(tempDir, "test.txt");
      fs.writeFileSync(filePath, "file content");

      const result = computeFileHash(filePath);

      expect(result.algorithm).toBe("sha256");
      expect(result.hash).toHaveLength(64);
      expect(result.formatted).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it("should detect file content changes", () => {
      const filePath = path.join(tempDir, "test.txt");
      fs.writeFileSync(filePath, "original content");

      const hash1 = computeFileHash(filePath);

      fs.writeFileSync(filePath, "modified content");

      const hash2 = computeFileHash(filePath);

      expect(hash1.hash).not.toBe(hash2.hash);
    });
  });

  describe("computeDirectoryHash", () => {
    it("should compute deterministic hash of directory contents", () => {
      // Create test files
      fs.writeFileSync(path.join(tempDir, "file1.js"), "const x = 1;");
      fs.writeFileSync(path.join(tempDir, "file2.js"), "const y = 2;");

      const hash1 = computeDirectoryHash(tempDir);
      const hash2 = computeDirectoryHash(tempDir);

      expect(hash1.hash).toBe(hash2.hash);
    });

    it("should detect file content changes", () => {
      fs.writeFileSync(path.join(tempDir, "file.js"), "original");

      const hash1 = computeDirectoryHash(tempDir);

      fs.writeFileSync(path.join(tempDir, "file.js"), "modified");

      const hash2 = computeDirectoryHash(tempDir);

      expect(hash1.hash).not.toBe(hash2.hash);
    });

    it("should detect new files", () => {
      fs.writeFileSync(path.join(tempDir, "file1.js"), "content");

      const hash1 = computeDirectoryHash(tempDir);

      fs.writeFileSync(path.join(tempDir, "file2.js"), "more content");

      const hash2 = computeDirectoryHash(tempDir);

      expect(hash1.hash).not.toBe(hash2.hash);
    });

    it("should detect file renames", () => {
      fs.writeFileSync(path.join(tempDir, "old.js"), "content");

      const hash1 = computeDirectoryHash(tempDir);

      fs.renameSync(path.join(tempDir, "old.js"), path.join(tempDir, "new.js"));

      const hash2 = computeDirectoryHash(tempDir);

      expect(hash1.hash).not.toBe(hash2.hash);
    });

    it("should exclude node_modules by default", () => {
      fs.writeFileSync(path.join(tempDir, "file.js"), "content");
      fs.mkdirSync(path.join(tempDir, "node_modules"));
      fs.writeFileSync(path.join(tempDir, "node_modules", "dep.js"), "dependency");

      const hash1 = computeDirectoryHash(tempDir);

      // Modify node_modules
      fs.writeFileSync(path.join(tempDir, "node_modules", "dep.js"), "modified dependency");

      const hash2 = computeDirectoryHash(tempDir);

      // Hash should be unchanged because node_modules is excluded
      expect(hash1.hash).toBe(hash2.hash);
    });

    it("should exclude hidden files by default", () => {
      fs.writeFileSync(path.join(tempDir, "file.js"), "content");
      fs.writeFileSync(path.join(tempDir, ".hidden.js"), "hidden");

      const hash1 = computeDirectoryHash(tempDir);

      fs.writeFileSync(path.join(tempDir, ".hidden.js"), "modified hidden");

      const hash2 = computeDirectoryHash(tempDir);

      expect(hash1.hash).toBe(hash2.hash);
    });

    it("should include hidden files when option is set", () => {
      fs.writeFileSync(path.join(tempDir, "file.js"), "content");
      fs.writeFileSync(path.join(tempDir, ".hidden.js"), "hidden");

      const hash1 = computeDirectoryHash(tempDir, { includeHidden: true });

      fs.writeFileSync(path.join(tempDir, ".hidden.js"), "modified hidden");

      const hash2 = computeDirectoryHash(tempDir, { includeHidden: true });

      expect(hash1.hash).not.toBe(hash2.hash);
    });

    it("should respect custom extensions", () => {
      fs.writeFileSync(path.join(tempDir, "file.js"), "js content");
      fs.writeFileSync(path.join(tempDir, "file.txt"), "txt content");

      const hash1 = computeDirectoryHash(tempDir, { extensions: [".js"] });

      fs.writeFileSync(path.join(tempDir, "file.txt"), "modified txt");

      const hash2 = computeDirectoryHash(tempDir, { extensions: [".js"] });

      // .txt changes should not affect hash
      expect(hash1.hash).toBe(hash2.hash);
    });

    it("should handle nested directories", () => {
      fs.mkdirSync(path.join(tempDir, "subdir"));
      fs.writeFileSync(path.join(tempDir, "file.js"), "root");
      fs.writeFileSync(path.join(tempDir, "subdir", "nested.js"), "nested");

      const hash1 = computeDirectoryHash(tempDir);

      fs.writeFileSync(path.join(tempDir, "subdir", "nested.js"), "modified nested");

      const hash2 = computeDirectoryHash(tempDir);

      expect(hash1.hash).not.toBe(hash2.hash);
    });
  });

  describe("verifyFileHash", () => {
    it("should return true for matching hash", () => {
      const filePath = path.join(tempDir, "test.txt");
      fs.writeFileSync(filePath, "test content");

      const hash = computeFileHash(filePath);

      expect(verifyFileHash(filePath, hash.formatted)).toBe(true);
      expect(verifyFileHash(filePath, hash.hash)).toBe(true);
    });

    it("should return false for non-matching hash", () => {
      const filePath = path.join(tempDir, "test.txt");
      fs.writeFileSync(filePath, "test content");

      expect(verifyFileHash(filePath, "sha256:0".repeat(64))).toBe(false);
    });
  });

  describe("verifyDirectoryHash", () => {
    it("should return true for matching hash", () => {
      fs.writeFileSync(path.join(tempDir, "file.js"), "content");

      const hash = computeDirectoryHash(tempDir);

      expect(verifyDirectoryHash(tempDir, hash.formatted)).toBe(true);
      expect(verifyDirectoryHash(tempDir, hash.hash)).toBe(true);
    });

    it("should return false for non-matching hash", () => {
      fs.writeFileSync(path.join(tempDir, "file.js"), "content");

      expect(verifyDirectoryHash(tempDir, "sha256:0".repeat(64))).toBe(false);
    });
  });

  describe("compareHashes", () => {
    it("should compare formatted hashes", () => {
      const hash = "sha256:abc123";
      expect(compareHashes(hash, hash)).toBe(true);
    });

    it("should compare raw hashes", () => {
      const hash = "a".repeat(64);
      expect(compareHashes(hash, hash)).toBe(true);
    });

    it("should compare mixed formats", () => {
      const rawHash = "a".repeat(64);
      const formattedHash = `sha256:${rawHash}`;

      expect(compareHashes(rawHash, formattedHash)).toBe(true);
      expect(compareHashes(formattedHash, rawHash)).toBe(true);
    });

    it("should be case insensitive", () => {
      const lower = "abcdef" + "0".repeat(58);
      const upper = "ABCDEF" + "0".repeat(58);

      expect(compareHashes(lower, upper)).toBe(true);
    });

    it("should return false for different hashes", () => {
      expect(compareHashes("a".repeat(64), "b".repeat(64))).toBe(false);
    });
  });

  describe("formatHash", () => {
    it("should add algorithm prefix", () => {
      const hash = "a".repeat(64);
      expect(formatHash(hash)).toBe(`sha256:${hash}`);
    });

    it("should not double-format", () => {
      const formatted = "sha256:" + "a".repeat(64);
      expect(formatHash(formatted)).toBe(formatted);
    });
  });

  describe("parseHash", () => {
    it("should parse formatted hash", () => {
      const result = parseHash("sha256:abc123");
      expect(result.algorithm).toBe("sha256");
      expect(result.hash).toBe("abc123");
    });

    it("should handle raw hash", () => {
      const hash = "a".repeat(64);
      const result = parseHash(hash);
      expect(result.algorithm).toBe("sha256");
      expect(result.hash).toBe(hash);
    });
  });

  describe("isValidHash", () => {
    it("should validate correct SHA-256 hashes", () => {
      expect(isValidHash("a".repeat(64))).toBe(true);
      expect(isValidHash("sha256:" + "a".repeat(64))).toBe(true);
      expect(isValidHash("0123456789abcdef".repeat(4))).toBe(true);
    });

    it("should reject invalid hashes", () => {
      expect(isValidHash("too-short")).toBe(false);
      expect(isValidHash("a".repeat(63))).toBe(false);
      expect(isValidHash("a".repeat(65))).toBe(false);
      expect(isValidHash("g".repeat(64))).toBe(false); // invalid hex
    });
  });
});
