import crypto from "node:crypto";
import { createJiti } from "jiti";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { OpenClawConfig } from "../config/config.js";
import type { GatewayRequestHandler } from "../gateway/server-methods/types.js";
import type {
  OpenClawPluginDefinition,
  OpenClawPluginModule,
  PluginDiagnostic,
  PluginLogger,
} from "./types.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { resolveUserPath } from "../utils.js";
import { clearPluginCommands } from "./commands.js";
import {
  normalizePluginsConfig,
  resolveEnableState,
  resolveMemorySlotDecision,
  type NormalizedPluginsConfig,
} from "./config-state.js";
import { discoverOpenClawPlugins } from "./discovery.js";
import { initializeGlobalHookRunner } from "./hook-runner-global.js";
import { loadPluginManifestRegistry } from "./manifest-registry.js";
import { createPluginRegistry, type PluginRecord, type PluginRegistry } from "./registry.js";
import { setActivePluginRegistry } from "./runtime.js";
import { createPluginRuntime } from "./runtime/index.js";
import { validateJsonSchemaValue } from "./schema-validator.js";
import {
  createAuditLogger,
  getDefaultLockfilePath,
  loadLockfile,
  normalizeSecurityConfig,
  verifyPluginSecurity,
  type AuditLogger,
  type PluginLockfile,
  type PluginSecurityConfig,
  type VerifyContext,
} from "./security/index.js";

export type PluginLoadResult = PluginRegistry;

export type PluginLoadOptions = {
  config?: OpenClawConfig;
  workspaceDir?: string;
  logger?: PluginLogger;
  coreGatewayHandlers?: Record<string, GatewayRequestHandler>;
  cache?: boolean;
  mode?: "full" | "validate";
};

const registryCache = new Map<string, PluginRegistry>();

const defaultLogger = () => createSubsystemLogger("plugins");

const resolvePluginSdkAlias = (): string | null => {
  try {
    const modulePath = fileURLToPath(import.meta.url);
    const isDistRuntime = modulePath.split(path.sep).includes("dist");
    const preferDist = process.env.VITEST || process.env.NODE_ENV === "test" || isDistRuntime;
    let cursor = path.dirname(modulePath);
    for (let i = 0; i < 6; i += 1) {
      const srcCandidate = path.join(cursor, "src", "plugin-sdk", "index.ts");
      const distCandidate = path.join(cursor, "dist", "plugin-sdk", "index.js");
      const orderedCandidates = preferDist
        ? [distCandidate, srcCandidate]
        : [srcCandidate, distCandidate];
      for (const candidate of orderedCandidates) {
        if (fs.existsSync(candidate)) {
          return candidate;
        }
      }
      const parent = path.dirname(cursor);
      if (parent === cursor) {
        break;
      }
      cursor = parent;
    }
  } catch {
    // ignore
  }
  return null;
};

function buildCacheKey(params: {
  workspaceDir?: string;
  plugins: NormalizedPluginsConfig;
}): string {
  const workspaceKey = params.workspaceDir ? resolveUserPath(params.workspaceDir) : "";
  return `${workspaceKey}::${JSON.stringify(params.plugins)}`;
}

function validatePluginConfig(params: {
  schema?: Record<string, unknown>;
  cacheKey?: string;
  value?: unknown;
}): { ok: boolean; value?: Record<string, unknown>; errors?: string[] } {
  const schema = params.schema;
  if (!schema) {
    return { ok: true, value: params.value as Record<string, unknown> | undefined };
  }
  const cacheKey = params.cacheKey ?? JSON.stringify(schema);
  const result = validateJsonSchemaValue({
    schema,
    cacheKey,
    value: params.value ?? {},
  });
  if (result.ok) {
    return { ok: true, value: params.value as Record<string, unknown> | undefined };
  }
  return { ok: false, errors: result.errors };
}

function resolvePluginModuleExport(moduleExport: unknown): {
  definition?: OpenClawPluginDefinition;
  register?: OpenClawPluginDefinition["register"];
} {
  const resolved =
    moduleExport &&
    typeof moduleExport === "object" &&
    "default" in (moduleExport as Record<string, unknown>)
      ? (moduleExport as { default: unknown }).default
      : moduleExport;
  if (typeof resolved === "function") {
    return {
      register: resolved as OpenClawPluginDefinition["register"],
    };
  }
  if (resolved && typeof resolved === "object") {
    const def = resolved as OpenClawPluginDefinition;
    const register = def.register ?? def.activate;
    return { definition: def, register };
  }
  return {};
}

function createPluginRecord(params: {
  id: string;
  name?: string;
  description?: string;
  version?: string;
  source: string;
  origin: PluginRecord["origin"];
  workspaceDir?: string;
  enabled: boolean;
  configSchema: boolean;
}): PluginRecord {
  return {
    id: params.id,
    name: params.name ?? params.id,
    description: params.description,
    version: params.version,
    source: params.source,
    origin: params.origin,
    workspaceDir: params.workspaceDir,
    enabled: params.enabled,
    status: params.enabled ? "loaded" : "disabled",
    toolNames: [],
    hookNames: [],
    channelIds: [],
    providerIds: [],
    gatewayMethods: [],
    cliCommands: [],
    services: [],
    commands: [],
    httpHandlers: 0,
    hookCount: 0,
    configSchema: params.configSchema,
    configUiHints: undefined,
    configJsonSchema: undefined,
  };
}

function pushDiagnostics(diagnostics: PluginDiagnostic[], append: PluginDiagnostic[]) {
  diagnostics.push(...append);
}

/**
 * Write verified content to a hash-addressed cache location.
 * This prevents TOCTOU attacks by ensuring the loader uses the exact content that was verified.
 */
function writeVerifiedContentToCache(params: {
  entryPath: string;
  content: Buffer;
}): string {
  const cacheDir = path.join(os.tmpdir(), "openclaw-plugin-cache");
  fs.mkdirSync(cacheDir, { recursive: true });

  // Use content hash as filename to ensure integrity
  const hash = crypto.createHash("sha256").update(params.content).digest("hex").slice(0, 16);
  const ext = path.extname(params.entryPath);
  const cachedPath = path.join(cacheDir, `verified-${hash}${ext}`);

  // Only write if not already cached (hash-based dedup)
  if (!fs.existsSync(cachedPath)) {
    fs.writeFileSync(cachedPath, params.content);
  }

  return cachedPath;
}

export function loadOpenClawPlugins(options: PluginLoadOptions = {}): PluginRegistry {
  const cfg = options.config ?? {};
  const logger = options.logger ?? defaultLogger();
  const validateOnly = options.mode === "validate";
  const normalized = normalizePluginsConfig(cfg.plugins);
  const cacheKey = buildCacheKey({
    workspaceDir: options.workspaceDir,
    plugins: normalized,
  });
  const cacheEnabled = options.cache !== false;
  if (cacheEnabled) {
    const cached = registryCache.get(cacheKey);
    if (cached) {
      setActivePluginRegistry(cached, cacheKey);
      return cached;
    }
  }

  // Clear previously registered plugin commands before reloading
  clearPluginCommands();

  const runtime = createPluginRuntime();
  const { registry, createApi } = createPluginRegistry({
    logger,
    runtime,
    coreGatewayHandlers: options.coreGatewayHandlers as Record<string, GatewayRequestHandler>,
  });

  const discovery = discoverOpenClawPlugins({
    workspaceDir: options.workspaceDir,
    extraPaths: normalized.loadPaths,
  });
  const manifestRegistry = loadPluginManifestRegistry({
    config: cfg,
    workspaceDir: options.workspaceDir,
    cache: options.cache,
    candidates: discovery.candidates,
    diagnostics: discovery.diagnostics,
  });
  pushDiagnostics(registry.diagnostics, manifestRegistry.diagnostics);

  // Initialize security verification
  const securityConfig = normalizeSecurityConfig(
    (cfg.plugins as Record<string, unknown> | undefined)?.security as Partial<PluginSecurityConfig> | undefined,
  );
  let auditLogger: AuditLogger | undefined;
  let lockfile: PluginLockfile | undefined;

  if (securityConfig.mode !== "off") {
    // Create audit logger if enabled
    if (securityConfig.audit.enabled) {
      auditLogger = createAuditLogger(securityConfig.audit);
    }

    // Load lockfile if available
    try {
      const lockfilePath = securityConfig.lockfilePath ?? getDefaultLockfilePath();
      const lockfileResult = loadLockfile(lockfilePath);
      if (lockfileResult) {
        lockfile = lockfileResult;
      }
    } catch (err) {
      logger.warn(`[plugins] failed to load lockfile: ${String(err)}`);
    }
  }

  const pluginSdkAlias = resolvePluginSdkAlias();
  const jiti = createJiti(import.meta.url, {
    interopDefault: true,
    extensions: [".ts", ".tsx", ".mts", ".cts", ".mtsx", ".ctsx", ".js", ".mjs", ".cjs", ".json"],
    ...(pluginSdkAlias
      ? {
          alias: { "openclaw/plugin-sdk": pluginSdkAlias },
        }
      : {}),
  });

  const manifestByRoot = new Map(
    manifestRegistry.plugins.map((record) => [record.rootDir, record]),
  );

  const seenIds = new Map<string, PluginRecord["origin"]>();
  const memorySlot = normalized.slots.memory;
  let selectedMemoryPluginId: string | null = null;
  let memorySlotMatched = false;

  for (const candidate of discovery.candidates) {
    const manifestRecord = manifestByRoot.get(candidate.rootDir);
    if (!manifestRecord) {
      continue;
    }
    const pluginId = manifestRecord.id;
    const existingOrigin = seenIds.get(pluginId);
    if (existingOrigin) {
      const record = createPluginRecord({
        id: pluginId,
        name: manifestRecord.name ?? pluginId,
        description: manifestRecord.description,
        version: manifestRecord.version,
        source: candidate.source,
        origin: candidate.origin,
        workspaceDir: candidate.workspaceDir,
        enabled: false,
        configSchema: Boolean(manifestRecord.configSchema),
      });
      record.status = "disabled";
      record.error = `overridden by ${existingOrigin} plugin`;
      registry.plugins.push(record);
      continue;
    }

    const enableState = resolveEnableState(pluginId, candidate.origin, normalized);
    const entry = normalized.entries[pluginId];
    const record = createPluginRecord({
      id: pluginId,
      name: manifestRecord.name ?? pluginId,
      description: manifestRecord.description,
      version: manifestRecord.version,
      source: candidate.source,
      origin: candidate.origin,
      workspaceDir: candidate.workspaceDir,
      enabled: enableState.enabled,
      configSchema: Boolean(manifestRecord.configSchema),
    });
    record.kind = manifestRecord.kind;
    record.configUiHints = manifestRecord.configUiHints;
    record.configJsonSchema = manifestRecord.configSchema;

    if (!enableState.enabled) {
      record.status = "disabled";
      record.error = enableState.reason;
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
      continue;
    }

    if (!manifestRecord.configSchema) {
      record.status = "error";
      record.error = "missing config schema";
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
      registry.diagnostics.push({
        level: "error",
        pluginId: record.id,
        source: record.source,
        message: record.error,
      });
      continue;
    }

    // Security verification before loading plugin code
    if (securityConfig.mode !== "off") {
      const verifyCtx: VerifyContext = {
        pluginId,
        source: candidate.source,
        origin: candidate.origin,
        manifest: {
          id: manifestRecord.id,
          version: manifestRecord.version,
          security: manifestRecord.security,
        },
        config: securityConfig,
        lockfile,
        auditLogger,
      };

      const securityResult = verifyPluginSecurity(verifyCtx);

      // Record security metadata
      record.securityVerified = securityResult.ok;
      record.securityLevel = securityResult.level;
      if (securityResult.findings) {
        record.securityFindings = securityResult.findings;
      }

      if (!securityResult.ok) {
        const reason = securityResult.reason ?? "security verification failed";
        logger.error(`[plugins] ${record.id} blocked by security: ${reason}`);
        record.status = "error";
        record.error = `security: ${reason}`;
        registry.plugins.push(record);
        seenIds.set(pluginId, candidate.origin);
        registry.diagnostics.push({
          level: "error",
          pluginId: record.id,
          source: record.source,
          message: `blocked by security policy: ${reason}`,
        });
        continue;
      }

      // Log warning for unsigned plugins in permissive mode
      if (securityConfig.mode === "permissive" && securityResult.level === "unsigned") {
        registry.diagnostics.push({
          level: "warn",
          pluginId: record.id,
          source: record.source,
          message: "plugin is unsigned (running in permissive mode)",
        });
      }

      // Log warning for security findings
      if (securityResult.findings && securityResult.findings.length > 0) {
        registry.diagnostics.push({
          level: "warn",
          pluginId: record.id,
          source: record.source,
          message: `${securityResult.findings.length} security finding(s) detected`,
        });
      }

      // If we have verified content, write it to cache for atomic loading
      // This prevents TOCTOU attacks by using the exact content that was hash-verified
      if (securityResult.verifiedContent) {
        const cachedPath = writeVerifiedContentToCache({
          entryPath: securityResult.verifiedContent.entryPath,
          content: securityResult.verifiedContent.content,
        });
        // Store the cached path for loading below
        (record as PluginRecord & { _verifiedSource?: string })._verifiedSource = cachedPath;
      }
    }

    // Determine source to load from: prefer verified cache to prevent TOCTOU
    const loadSource =
      (record as PluginRecord & { _verifiedSource?: string })._verifiedSource ?? candidate.source;

    let mod: OpenClawPluginModule | null = null;
    try {
      mod = jiti(loadSource) as OpenClawPluginModule;
    } catch (err) {
      logger.error(`[plugins] ${record.id} failed to load from ${record.source}: ${String(err)}`);
      record.status = "error";
      record.error = String(err);
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
      registry.diagnostics.push({
        level: "error",
        pluginId: record.id,
        source: record.source,
        message: `failed to load plugin: ${String(err)}`,
      });
      continue;
    }

    const resolved = resolvePluginModuleExport(mod);
    const definition = resolved.definition;
    const register = resolved.register;

    if (definition?.id && definition.id !== record.id) {
      registry.diagnostics.push({
        level: "warn",
        pluginId: record.id,
        source: record.source,
        message: `plugin id mismatch (config uses "${record.id}", export uses "${definition.id}")`,
      });
    }

    record.name = definition?.name ?? record.name;
    record.description = definition?.description ?? record.description;
    record.version = definition?.version ?? record.version;
    const manifestKind = record.kind as string | undefined;
    const exportKind = definition?.kind as string | undefined;
    if (manifestKind && exportKind && exportKind !== manifestKind) {
      registry.diagnostics.push({
        level: "warn",
        pluginId: record.id,
        source: record.source,
        message: `plugin kind mismatch (manifest uses "${manifestKind}", export uses "${exportKind}")`,
      });
    }
    record.kind = definition?.kind ?? record.kind;

    if (record.kind === "memory" && memorySlot === record.id) {
      memorySlotMatched = true;
    }

    const memoryDecision = resolveMemorySlotDecision({
      id: record.id,
      kind: record.kind,
      slot: memorySlot,
      selectedId: selectedMemoryPluginId,
    });

    if (!memoryDecision.enabled) {
      record.enabled = false;
      record.status = "disabled";
      record.error = memoryDecision.reason;
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
      continue;
    }

    if (memoryDecision.selected && record.kind === "memory") {
      selectedMemoryPluginId = record.id;
    }

    const validatedConfig = validatePluginConfig({
      schema: manifestRecord.configSchema,
      cacheKey: manifestRecord.schemaCacheKey,
      value: entry?.config,
    });

    if (!validatedConfig.ok) {
      logger.error(`[plugins] ${record.id} invalid config: ${validatedConfig.errors?.join(", ")}`);
      record.status = "error";
      record.error = `invalid config: ${validatedConfig.errors?.join(", ")}`;
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
      registry.diagnostics.push({
        level: "error",
        pluginId: record.id,
        source: record.source,
        message: record.error,
      });
      continue;
    }

    if (validateOnly) {
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
      continue;
    }

    if (typeof register !== "function") {
      logger.error(`[plugins] ${record.id} missing register/activate export`);
      record.status = "error";
      record.error = "plugin export missing register/activate";
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
      registry.diagnostics.push({
        level: "error",
        pluginId: record.id,
        source: record.source,
        message: record.error,
      });
      continue;
    }

    const api = createApi(record, {
      config: cfg,
      pluginConfig: validatedConfig.value,
    });

    try {
      const result = register(api);
      if (result && typeof result.then === "function") {
        registry.diagnostics.push({
          level: "warn",
          pluginId: record.id,
          source: record.source,
          message: "plugin register returned a promise; async registration is ignored",
        });
      }
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
    } catch (err) {
      logger.error(
        `[plugins] ${record.id} failed during register from ${record.source}: ${String(err)}`,
      );
      record.status = "error";
      record.error = String(err);
      registry.plugins.push(record);
      seenIds.set(pluginId, candidate.origin);
      registry.diagnostics.push({
        level: "error",
        pluginId: record.id,
        source: record.source,
        message: `plugin failed during register: ${String(err)}`,
      });
    }
  }

  if (typeof memorySlot === "string" && !memorySlotMatched) {
    registry.diagnostics.push({
      level: "warn",
      message: `memory slot plugin not found or not marked as memory: ${memorySlot}`,
    });
  }

  if (cacheEnabled) {
    registryCache.set(cacheKey, registry);
  }
  setActivePluginRegistry(registry, cacheKey);
  initializeGlobalHookRunner(registry);
  return registry;
}
