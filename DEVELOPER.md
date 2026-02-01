# OpenClaw Project Summary

**OpenClaw** is a local-first personal AI assistant platform that runs on your own devices. It supports 15+ messaging channels (WhatsApp, Telegram, Discord, Slack, Signal, iMessage, etc.) and provides an always-on gateway with multi-agent capabilities.

**Version:** 2026.1.30 | **Runtime:** Node 22+ | **Language:** TypeScript (ESM)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MESSAGING CHANNELS                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │WhatsApp │ │Telegram │ │ Discord │ │  Slack  │ │ Signal  │ │iMessage │   │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘   │
│       │           │           │           │           │           │         │
│       └───────────┴───────────┴─────┬─────┴───────────┴───────────┘         │
└─────────────────────────────────────┼───────────────────────────────────────┘
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          OPENCLAW GATEWAY (:18789)                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Channel    │  │   Routing    │  │   Session    │  │   Plugin     │    │
│  │   Manager    │  │   Engine     │  │   Store      │  │   Loader     │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                 │                 │             │
│         └─────────────────┴────────┬────────┴─────────────────┘             │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         AGENT RUNTIME (pi-mono)                      │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │   │
│  │  │  Tools  │  │ Memory  │  │ Sandbox │  │ Skills  │  │ Models  │   │   │
│  │  │  (15+)  │  │(LanceDB)│  │(Docker) │  │  (.md)  │  │(failover│   │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│   macOS App   │           │   iOS App     │           │  Android App  │
│  (Menu Bar)   │           │  (Companion)  │           │  (Companion)  │
│   SwiftUI     │           │   SwiftUI     │           │    Kotlin     │
└───────────────┘           └───────────────┘           └───────────────┘
```

---

## Project Filesystem Structure

```
openclaw/
├── src/                          # Core TypeScript source (~200k LOC)
│   ├── agents/                   #   Agent runtime (250+ files)
│   │   ├── pi-embedded-runner.ts #     Main execution engine
│   │   ├── pi-tools.ts           #     Tool definitions
│   │   ├── sandbox.ts            #     Docker isolation
│   │   ├── skills.ts             #     Skill loading
│   │   └── auth-profiles.ts      #     Model auth (OAuth/API keys)
│   ├── gateway/                  #   Gateway control plane (60+ files)
│   │   ├── server.impl.ts        #     Main server init
│   │   ├── server-chat.ts        #     Chat event handling
│   │   ├── server-channels.ts    #     Channel lifecycle
│   │   └── server-ws-runtime.ts  #     WebSocket protocol
│   ├── routing/                  #   Message routing
│   │   ├── resolve-route.ts      #     Route matching engine
│   │   └── bindings.ts           #     Agent bindings config
│   ├── channels/                 #   Channel abstraction
│   │   ├── registry.ts           #     Driver registry
│   │   └── plugin/               #     Plugin channel interface
│   ├── auto-reply/               #   Message processing (60+ files)
│   │   ├── reply.ts              #     Main reply orchestrator
│   │   ├── dispatch.ts           #     Trigger detection
│   │   └── queue.ts              #     Message queueing
│   ├── config/                   #   Configuration system (100+ files)
│   │   ├── config.ts             #     Config loader
│   │   ├── types.ts              #     TypeScript types
│   │   └── zod-schema.ts         #     Runtime validation
│   ├── plugins/                  #   Plugin system
│   │   ├── loader.ts             #     Dynamic ESM loading
│   │   ├── discovery.ts          #     Extension scanning
│   │   └── security/             #     skill-guardian verification
│   ├── cli/                      #   CLI framework
│   ├── commands/                 #   CLI commands (150+)
│   ├── telegram/                 #   Telegram driver (grammY)
│   ├── discord/                  #   Discord driver (discord.js)
│   ├── slack/                    #   Slack driver (Bolt)
│   ├── signal/                   #   Signal driver
│   ├── imessage/                 #   iMessage driver
│   ├── web/                      #   WhatsApp driver (Baileys)
│   ├── media/                    #   Media pipeline
│   ├── memory/                   #   Embedding & retrieval
│   ├── browser/                  #   Playwright automation
│   ├── tts/                      #   Text-to-speech
│   └── ...                       #   (50+ more modules)
│
├── extensions/                   # Plugin ecosystem (30+)
│   ├── bluebubbles/              #   iMessage via BlueBubbles
│   ├── matrix/                   #   Matrix protocol
│   ├── msteams/                  #   Microsoft Teams
│   ├── voice-call/               #   Twilio voice calls
│   ├── memory-lancedb/           #   Vector memory
│   ├── llm-task/                 #   LLM sub-task tool
│   └── ...                       #   (25+ more)
│
├── apps/                         # Native applications
│   ├── macos/                    #   SwiftUI menu bar app
│   │   └── Sources/OpenClaw/     #     Swift source
│   ├── ios/                      #   iOS companion
│   └── android/                  #   Android companion
│
├── docs/                         # Mintlify documentation
│   ├── cli/                      #   CLI reference
│   ├── channels/                 #   Channel setup guides
│   ├── gateway/                  #   Gateway config
│   └── plugins/                  #   Plugin development
│
├── skills/                       # Agent skills (.md + scripts)
├── scripts/                      # Build & dev helpers
├── patches/                      # pnpm dependency patches
└── dist/                         # Compiled output
```

---

## Message Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           INBOUND MESSAGE FLOW                          │
└─────────────────────────────────────────────────────────────────────────┘

  User sends message
        │
        ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   Channel     │────▶│   Gateway     │────▶│   Routing     │
│   Driver      │     │   Receives    │     │   Engine      │
│ (WhatsApp/..) │     │   Message     │     │               │
└───────────────┘     └───────────────┘     └───────┬───────┘
                                                    │
                      ┌─────────────────────────────┘
                      ▼
              ┌───────────────┐
              │ Match Binding │
              │ (channel +    │
              │  account +    │
              │  peer)        │
              └───────┬───────┘
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
┌───────────────┐           ┌───────────────┐
│  Agent: main  │           │  Agent: work  │
│  Workspace A  │           │  Workspace B  │
└───────┬───────┘           └───────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│                      AGENT EXECUTION                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ Load Session│─▶│ Run pi-mono │─▶│ Execute     │           │
│  │ History     │  │ Agent Loop  │  │ Tools       │           │
│  └─────────────┘  └─────────────┘  └──────┬──────┘           │
│                                           │                   │
│  Tools: bash, browser, read, write, edit, canvas, etc.       │
└───────────────────────────────────────────┼───────────────────┘
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │ Stream Blocks │
                                    │ (real-time)   │
                                    └───────┬───────┘
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │ Chunk Message │
                                    │ (size limits) │
                                    └───────┬───────┘
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │ Deliver via   │
                                    │ Channel       │
                                    └───────────────┘
```

---

## Gateway Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GATEWAY SERVER (port 18789)                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      TRANSPORT LAYER                             │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │   │
│  │  │  WebSocket  │  │    HTTP     │  │   mDNS/     │              │   │
│  │  │  Protocol   │  │  Endpoints  │  │  Bonjour    │              │   │
│  │  │  (RPC)      │  │  (OpenAI)   │  │  Discovery  │              │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                    │                                    │
│  ┌─────────────────────────────────▼───────────────────────────────┐   │
│  │                      CORE SERVICES                               │   │
│  │                                                                  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │   │
│  │  │   Channel    │  │    Auth &    │  │   Config     │           │   │
│  │  │   Manager    │  │   Pairing    │  │   Watcher    │           │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │   │
│  │                                                                  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │   │
│  │  │   Plugin     │  │    Cron      │  │   Hook       │           │   │
│  │  │   Registry   │  │   Scheduler  │  │   System     │           │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │   │
│  │                                                                  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │   │
│  │  │   Session    │  │   Skills     │  │   Node       │           │   │
│  │  │   Store      │  │   Watcher    │  │   Manager    │           │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Plugin System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PLUGIN DISCOVERY ORDER                          │
└─────────────────────────────────────────────────────────────────────────┘

  1. Config paths           plugins.load.paths (explicit)
        │
        ▼
  2. Workspace extensions   <workspace>/.openclaw/extensions/*
        │
        ▼
  3. Global extensions      ~/.openclaw/extensions/*
        │
        ▼
  4. Bundled extensions     <openclaw>/extensions/* (disabled by default)


┌─────────────────────────────────────────────────────────────────────────┐
│                          PLUGIN TYPES                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │    CHANNELS     │  │    PROVIDERS    │  │     TOOLS       │         │
│  │  ─────────────  │  │  ─────────────  │  │  ─────────────  │         │
│  │  • matrix       │  │  • gemini-cli   │  │  • llm-task     │         │
│  │  • msteams      │  │  • qwen-portal  │  │  • lobster      │         │
│  │  • bluebubbles  │  │  • minimax      │  │  • diagnostics  │         │
│  │  • zalo         │  │  • copilot      │  │                 │         │
│  │  • nostr        │  │                 │  │                 │         │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐                               │
│  │    MEMORY       │  │    VOICE        │                               │
│  │  ─────────────  │  │  ─────────────  │                               │
│  │  • memory-core  │  │  • voice-call   │                               │
│  │  • memory-lance │  │    (Twilio)     │                               │
│  └─────────────────┘  └─────────────────┘                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────┐
│                    SECURITY VERIFICATION (skill-guardian)               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Plugin Load Request                                                   │
│          │                                                              │
│          ▼                                                              │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │
│   │    Hash     │───▶│  Signature  │───▶│   Static    │                │
│   │ Verification│    │ Validation  │    │  Analysis   │                │
│   │  (SHA-256)  │    │  (Ed25519)  │    │  (Scanner)  │                │
│   └─────────────┘    └─────────────┘    └──────┬──────┘                │
│                                                │                        │
│          ┌─────────────────────────────────────┘                        │
│          ▼                                                              │
│   ┌─────────────────────────────────────────────────────┐              │
│   │              TRUST LEVEL ASSIGNMENT                  │              │
│   │  unsigned → hashed → signed → verified               │              │
│   └─────────────────────────────────────────────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Data Storage Layout

```
~/.openclaw/                          # State directory ($OPENCLAW_STATE_DIR)
├── openclaw.json                     # Main config file (JSON5/YAML)
├── credentials/                      # Channel credentials
│   ├── whatsapp/<accountId>/         #   WhatsApp session (Baileys)
│   │   └── creds.json
│   ├── telegram-allowFrom.json       #   DM allowlists
│   ├── discord-allowFrom.json
│   └── oauth.json                    #   Legacy OAuth import
├── agents/                           # Per-agent state
│   └── <agentId>/
│       ├── agent/
│       │   └── auth-profiles.json    #   Model auth (keys, OAuth)
│       └── sessions/
│           ├── sessions.json         #   Session index
│           └── <sessionId>.jsonl     #   Transcripts (JSONL)
├── extensions/                       # Installed plugins
│   └── <pluginId>/
│       ├── package.json
│       └── dist/
├── plugins.lock                      # HMAC-authenticated lockfile
├── plugins.secret                    # Lockfile signing key
├── audit/
│   └── plugins.jsonl                 # Security audit log
├── sandboxes/                        # Docker sandbox workspaces
└── workspace/                        # Default agent workspace
```

---

## Supported Channels

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MESSAGING CHANNELS                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  BUILT-IN (src/)                    PLUGIN-BASED (extensions/)          │
│  ────────────────                   ──────────────────────────          │
│  ┌─────────────┐                    ┌─────────────┐                     │
│  │  WhatsApp   │ ◄── Baileys WS     │ BlueBubbles │ ◄── iMessage alt    │
│  ├─────────────┤                    ├─────────────┤                     │
│  │  Telegram   │ ◄── grammY         │   Matrix    │ ◄── Decentralized   │
│  ├─────────────┤                    ├─────────────┤                     │
│  │   Discord   │ ◄── discord.js     │  MS Teams   │ ◄── Graph API       │
│  ├─────────────┤                    ├─────────────┤                     │
│  │    Slack    │ ◄── Bolt           │ Mattermost  │ ◄── Self-hosted     │
│  ├─────────────┤                    ├─────────────┤                     │
│  │   Signal    │ ◄── signal-cli     │    Zalo     │ ◄── Vietnam         │
│  ├─────────────┤                    ├─────────────┤                     │
│  │  iMessage   │ ◄── macOS native   │   Twitch    │ ◄── Streaming       │
│  ├─────────────┤                    ├─────────────┤                     │
│  │    LINE     │ ◄── @line/bot-sdk  │    Nostr    │ ◄── Decentralized   │
│  ├─────────────┤                    ├─────────────┤                     │
│  │ Google Chat │ ◄── Workspace API  │  Nextcloud  │ ◄── Self-hosted     │
│  └─────────────┘                    └─────────────┘                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## CLI Command Structure

```
openclaw
├── gateway              # Start the always-on gateway
├── agent                # Execute agent turns
│   ├── --message        #   Send a message
│   └── --session        #   Target session
├── onboard              # Interactive setup wizard
├── status               # System health check
│   ├── --all            #   Full pasteable output
│   └── --deep           #   Live probes
├── channels             # Channel management
│   ├── status           #   Connection status
│   └── list             #   Available channels
├── models               # Model configuration
│   ├── list             #   Show available
│   ├── auth             #   Manage auth
│   └── status           #   Per-agent status
├── agents               # Agent management
│   ├── list
│   ├── add
│   └── remove
├── plugins              # Plugin management
│   ├── list             #   Installed plugins
│   ├── install          #   Add plugin
│   ├── enable/disable
│   └── doctor           #   Diagnose issues
├── pairing              # Device pairing
│   ├── list
│   └── approve
├── config               # Configuration
│   ├── get
│   ├── set
│   └── edit
├── security             # Security tools
│   └── audit            #   Run security audit
├── doctor               # Diagnose & fix issues
└── ...                  # (150+ more commands)
```

---

## Key Dependencies

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          CORE DEPENDENCIES                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  AGENT RUNTIME          MESSAGING              WEB/HTTP                 │
│  ─────────────          ─────────              ────────                 │
│  @mariozechner/pi-*     @whiskeysockets/       hono                     │
│  (Anthropic pi-mono)    baileys (WhatsApp)     (HTTP framework)         │
│                         grammy (Telegram)                               │
│  BROWSER                discord.js             CLI                      │
│  ───────                @slack/bolt            ───                      │
│  playwright-core        signal-utils           commander                │
│                         @line/bot-sdk          @clack/prompts           │
│  STORAGE                                                                │
│  ───────                VALIDATION             MEDIA                    │
│  sqlite-vec             ──────────             ─────                    │
│  (vector DB)            zod                    sharp (images)           │
│                         ajv (JSON Schema)      ffmpeg (audio)           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Summary

OpenClaw is a **local-first, multi-channel AI assistant platform** with:

| Aspect | Details |
|--------|---------|
| **Architecture** | Gateway control plane + embedded agent runtime |
| **Channels** | 15+ messaging platforms (built-in + plugins) |
| **Agents** | Multi-agent with isolated workspaces & auth |
| **Tools** | 15+ built-in (bash, browser, canvas, etc.) |
| **Plugins** | 30+ extensions for channels, tools, memory |
| **Security** | skill-guardian verification, sandboxing, pairing |
| **Apps** | macOS menu bar, iOS/Android companions |
| **Codebase** | ~300k LOC TypeScript, 3000+ source files |
