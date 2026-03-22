/**
 * Deterministic canonicalization for Faramesh client-side hashing.
 *
 * This module mirrors the canonicalization logic in faramesh-core to enable
 * clients to compute request_hash locally before submitting actions.
 *
 * @example
 * ```typescript
 * import { computeRequestHash } from "@faramesh/sdk";
 *
 * const payload = { agent_id: "test", tool: "http", operation: "get", params: {} };
 * const hash = computeRequestHash(payload);
 * ```
 */

import * as crypto from "crypto";

/**
 * Error thrown when canonicalization fails.
 */
export class CanonicalizeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizeError";
    Object.setPrototypeOf(this, CanonicalizeError.prototype);
  }
}

// Fields to exclude from action payloads (ephemeral/internal)
const ACTION_EXCLUDE_FIELDS = new Set([
  "id",
  "approval_token",
  "created_at",
  "updated_at",
  "tenant_id",
  "project_id",
  "version",
  "decision",
  "status",
  "reason",
  "risk_level",
  "policy_version",
  "policy_hash",
  "runtime_version",
  "profile_id",
  "profile_version",
  "profile_hash",
  "provenance_id",
  "outcome",
  "reason_code",
  "reason_details",
  "request_hash",
]);

/**
 * Normalize a float to canonical string representation.
 *
 * Rules:
 * - No exponent notation (1e3 → 1000)
 * - No trailing zeros (1.50 → 1.5)
 * - Whole numbers have no decimal point (1.0 → 1)
 * - NaN, Infinity, -Infinity → CanonicalizeError
 */
function normalizeFloat(value: number): string {
  if (Number.isNaN(value)) {
    throw new CanonicalizeError("NaN is not allowed in canonical JSON");
  }
  if (!Number.isFinite(value)) {
    throw new CanonicalizeError("Infinity is not allowed in canonical JSON");
  }

  // Handle zero explicitly
  if (value === 0) {
    return "0";
  }

  // Convert to string representation
  let str = value.toString();

  // Handle scientific notation
  if (str.includes("e") || str.includes("E")) {
    // Expand scientific notation
    const [mantissa, exponentStr] = str.toLowerCase().split("e");
    const exponent = parseInt(exponentStr, 10);
    const parts = mantissa.split(".");
    let intPart = parts[0].replace("-", "");
    let fracPart = parts[1] || "";
    const isNegative = value < 0;

    if (exponent > 0) {
      // Move decimal point right
      if (fracPart.length <= exponent) {
        str = intPart + fracPart + "0".repeat(exponent - fracPart.length);
      } else {
        str =
          intPart +
          fracPart.slice(0, exponent) +
          "." +
          fracPart.slice(exponent);
      }
    } else {
      // Move decimal point left
      const absExp = Math.abs(exponent);
      const allDigits = intPart + fracPart;
      if (absExp >= allDigits.length) {
        str =
          "0." +
          "0".repeat(absExp - allDigits.length) +
          allDigits;
      } else {
        str =
          allDigits.slice(0, allDigits.length - absExp) +
          "." +
          allDigits.slice(allDigits.length - absExp);
      }
    }

    if (isNegative && !str.startsWith("-")) {
      str = "-" + str;
    }
  }

  // Remove trailing zeros after decimal point
  if (str.includes(".")) {
    str = str.replace(/\.?0+$/, "");
  }

  return str;
}

/**
 * Serialize a string to canonical JSON representation.
 */
function serializeString(value: string): string {
  let result = '"';

  for (const char of value) {
    const code = char.charCodeAt(0);

    if (char === '"') {
      result += '\\"';
    } else if (char === "\\") {
      result += "\\\\";
    } else if (char === "\b") {
      result += "\\b";
    } else if (char === "\f") {
      result += "\\f";
    } else if (char === "\n") {
      result += "\\n";
    } else if (char === "\r") {
      result += "\\r";
    } else if (char === "\t") {
      result += "\\t";
    } else if (code < 0x20) {
      result += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      result += char;
    }
  }

  result += '"';
  return result;
}

/**
 * Serialize an object to canonical JSON with sorted keys.
 */
function serializeObject(value: Record<string, unknown>): string {
  const keys = Object.keys(value).sort();
  const parts: string[] = [];

  for (const key of keys) {
    if (typeof key !== "string") {
      throw new CanonicalizeError(
        `Dict keys must be strings, got ${typeof key}: ${key}`
      );
    }
    const keyStr = serializeString(key);
    const valStr = serializeValue(value[key]);
    parts.push(`${keyStr}:${valStr}`);
  }

  return "{" + parts.join(",") + "}";
}

/**
 * Serialize an array to canonical JSON (order preserved).
 */
function serializeArray(value: unknown[]): string {
  const parts = value.map((item) => serializeValue(item));
  return "[" + parts.join(",") + "]";
}

/**
 * Serialize a value to canonical JSON string.
 */
function serializeValue(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (value === undefined) {
    return "null";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    return normalizeFloat(value);
  }

  if (typeof value === "string") {
    return serializeString(value);
  }

  if (Array.isArray(value)) {
    return serializeArray(value);
  }

  if (typeof value === "object") {
    return serializeObject(value as Record<string, unknown>);
  }

  throw new CanonicalizeError(
    `Cannot canonicalize value of type ${typeof value}: ${value}`
  );
}

/**
 * Canonicalize an object to a deterministic JSON string.
 *
 * Guarantees:
 * - Dict keys sorted lexicographically
 * - Arrays preserve order
 * - UTF-8 compatible (ensure_ascii=false)
 * - No NaN, Infinity, -Infinity
 * - Floats normalized: no exponent, no trailing zeros
 *
 * @param obj - Any JSON-serializable object
 * @returns Canonical JSON string
 * @throws CanonicalizeError if canonicalization fails
 */
export function canonicalize(obj: unknown): string {
  // Deep copy to ensure we never mutate input
  const objCopy = JSON.parse(JSON.stringify(obj));
  return serializeValue(objCopy);
}

/**
 * Canonicalize an action payload for hashing.
 *
 * Drops ephemeral/internal fields (id, approval_token, timestamps, etc.)
 * and produces canonical string.
 *
 * @param payload - Action payload with agent_id, tool, operation, params, context
 * @returns Canonical string representation
 * @throws CanonicalizeError if canonicalization fails
 */
export function canonicalizeActionPayload(
  payload: Record<string, unknown>
): string {
  const cleanPayload: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(payload)) {
    if (ACTION_EXCLUDE_FIELDS.has(key) || key.startsWith("_")) {
      continue;
    }
    cleanPayload[key] = value;
  }

  return canonicalize(cleanPayload);
}

/**
 * Compute SHA-256 hash of canonicalized action payload.
 *
 * This produces the same hash as the Faramesh server, enabling
 * clients to verify request_hash matches before/after submission.
 *
 * @param payload - Action payload dict (agent_id, tool, operation, params, context)
 * @returns SHA-256 hex digest (64 characters)
 * @throws CanonicalizeError if canonicalization fails
 *
 * @example
 * ```typescript
 * const payload = {
 *   agent_id: "test",
 *   tool: "http",
 *   operation: "get",
 *   params: { url: "https://example.com" },
 *   context: {}
 * };
 * const hash = computeRequestHash(payload);
 * console.log(hash); // 64-char hex string
 * ```
 */
export function computeRequestHash(payload: Record<string, unknown>): string {
  const canonicalStr = canonicalizeActionPayload(payload);
  const canonicalBytes = Buffer.from(canonicalStr, "utf-8");
  return crypto.createHash("sha256").update(canonicalBytes).digest("hex");
}

/**
 * Compute SHA-256 hash of the canonical JSON representation.
 *
 * @param obj - Any JSON-serializable object
 * @returns SHA-256 hex digest (64 characters)
 * @throws CanonicalizeError if canonicalization fails
 */
export function computeHash(obj: unknown): string {
  const canonicalStr = canonicalize(obj);
  const canonicalBytes = Buffer.from(canonicalStr, "utf-8");
  return crypto.createHash("sha256").update(canonicalBytes).digest("hex");
}
