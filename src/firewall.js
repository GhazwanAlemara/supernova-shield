"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");

const SHIELD_DIR = path.join(os.homedir(), ".supernova-shield");
const AUDIT_LOG_PATH = path.join(SHIELD_DIR, "audit.jsonl");
const CONFIG_PATH = path.join(SHIELD_DIR, "config.json");
const MAX_INSPECT_CHARS = 100000;

const RULES = [
  {
    id: "PROMPT_INJECTION_OVERRIDE",
    severity: "CRITICAL",
    pattern: /(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)|disregard\s+system\s+prompt|reveal\s+(your\s+)?system\s+prompt|you\s+are\s+now\s+(in\s+)?developer\s+mode|bypass\s+all\s+safety)/i,
    detail: "Instruction override or jailbreak attempt detected in tool arguments."
  },
  {
    id: "SSRF_METADATA_OR_PRIVATE_NET",
    severity: "CRITICAL",
    pattern: /(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|::1|::ffff:169\.254\.169\.254|https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\]))/i,
    detail: "SSRF target pointing to cloud metadata, loopback, or RFC-1918 private network detected."
  },
  {
    id: "SECRET_EXFILTRATION_LEAK",
    severity: "CRITICAL",
    pattern: /(sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----)/,
    detail: "Live API key or private cryptographic key material detected inside MCP payload."
  },
  {
    id: "PATH_TRAVERSAL_ESCAPE",
    severity: "HIGH",
    pattern: /(\.\.[\/\\]\.\.[\/\\]|\/etc\/passwd|\/etc\/shadow|C:\\Windows\\System32|\/\.env\b|\/\.ssh\/id_)/i,
    detail: "Filesystem path traversal or sensitive credential file reference detected."
  },
  {
    id: "COMMAND_INJECTION_SHELL",
    severity: "CRITICAL",
    pattern: /(;\s*(rm\s+-rf|curl\s+|wget\s+|nc\s+-e|bash\s+-i|powershell\s+-enc)|`[^`\r\n]{0,512}\b(curl|wget|bash|sh|nc)\b|`|\$\(\s*(curl|wget|cat\s+\/etc))/i,
    detail: "Shell metacharacter or remote payload execution pattern detected."
  }
];

function inspectPayload(input) {
  const started = process.hrtime.bigint();
  const rawText = typeof input === "string" ? input : JSON.stringify(input || {});
  const text = rawText.length > MAX_INSPECT_CHARS ? rawText.slice(0, MAX_INSPECT_CHARS) : rawText;
  const findings = [];

  if (rawText.length > MAX_INSPECT_CHARS) {
    findings.push({
      rule_id: "PAYLOAD_SIZE_LIMIT",
      severity: "HIGH",
      detail: `Payload length (${rawText.length} chars) exceeds ${MAX_INSPECT_CHARS} safe limit.`
    });
  }

  for (const rule of RULES) {
    if (rule.pattern.test(text)) {
      findings.push({
        rule_id: rule.id,
        severity: rule.severity,
        detail: rule.detail
      });
    }
  }

  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const payloadSha256 = crypto.createHash("sha256").update(rawText).digest("hex");

  return {
    allowed: findings.length === 0,
    blocked: findings.length > 0,
    latency_ms: Math.round(elapsedMs * 1000) / 1000,
    findings_count: findings.length,
    findings,
    payload_sha256: payloadSha256
  };
}

class BudgetTracker {
  constructor(maxBudgetUsd = 5.0, defaultCallCostUsd = 0.01) {
    const parsed = Number(maxBudgetUsd);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error("Budget cap must be a finite positive USD amount > 0.");
    }
    this.maxBudgetUsd = parsed;
    this.defaultCallCostUsd = Math.max(0.0001, Number(defaultCallCostUsd) || 0.01);
    this.spentUsd = 0.0;
    this.callCount = 0;
  }

  canExecute(estimatedCostUsd = this.defaultCallCostUsd) {
    const nextTotal = this.spentUsd + estimatedCostUsd;
    if (nextTotal > this.maxBudgetUsd + 1e-9) {
      return {
        allowed: false,
        spentUsd: Math.round(this.spentUsd * 10000) / 10000,
        maxBudgetUsd: this.maxBudgetUsd,
        reason: `Daily MCP proxy budget ceiling ($${this.maxBudgetUsd.toFixed(2)}) reached after ${this.callCount} calls.`
      };
    }
    this.spentUsd = nextTotal;
    this.callCount += 1;
    return {
      allowed: true,
      spentUsd: Math.round(this.spentUsd * 10000) / 10000,
      remainingUsd: Math.round((this.maxBudgetUsd - this.spentUsd) * 10000) / 10000
    };
  }
}

function appendAuditEntry(record) {
  try {
    fs.mkdirSync(SHIELD_DIR, { recursive: true, mode: 0o700 });
    let prevHash = "0".repeat(64);
    if (fs.existsSync(AUDIT_LOG_PATH)) {
      const lines = fs.readFileSync(AUDIT_LOG_PATH, "utf8").trim().split("\n").filter(Boolean);
      if (lines.length > 0) {
        const last = JSON.parse(lines[lines.length - 1]);
        if (last && last.entry_hash) prevHash = last.entry_hash;
      }
    }
    const base = {
      timestamp: new Date().toISOString(),
      prev_hash: prevHash,
      ...record
    };
    const entryHash = crypto.createHash("sha256").update(JSON.stringify(base)).digest("hex");
    const full = { ...base, entry_hash: entryHash };
    fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(full) + "\n", { encoding: "utf8", mode: 0o600 });
    return full;
  } catch (err) {
    return { error: err.message, ...record };
  }
}

function loadSavedApiKey() {
  const envKey = (process.env.SUPERNOVA_API_KEY || "").trim();
  if (envKey) return envKey;
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
      return (parsed.api_key || "").trim();
    }
  } catch (_) {}
  return "";
}

function saveApiKey(apiKey) {
  fs.mkdirSync(SHIELD_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    CONFIG_PATH,
    JSON.stringify({ api_key: apiKey.trim(), updated_at: new Date().toISOString() }, null, 2),
    { encoding: "utf8", mode: 0o600 }
  );
  try {
    fs.chmodSync(CONFIG_PATH, 0o600);
  } catch (_) {}
}

module.exports = {
  AUDIT_LOG_PATH,
  BudgetTracker,
  CONFIG_PATH,
  RULES,
  appendAuditEntry,
  inspectPayload,
  loadSavedApiKey,
  saveApiKey
};
