/**
 * Policy validation and testing helpers
 */

import * as fs from "fs";
import * as path from "path";
import { FaraCoreError, FaraCorePolicyError } from "./types";
import { submitAction } from "./client";

/**
 * Validate a policy YAML/JSON file
 */
export async function validatePolicyFile(policyPath: string): Promise<void> {
  if (!fs.existsSync(policyPath)) {
    throw new FaraCoreError(`Policy file not found: ${policyPath}`);
  }

  let content: string;
  try {
    content = fs.readFileSync(policyPath, "utf-8");
  } catch (error: any) {
    throw new FaraCoreError(`Failed to read policy file: ${error.message}`);
  }

  // Try POST to /v1/policy/validate if it exists
  // Note: This would require makeRequest to be exported or a dedicated function
  // For now, we'll do local validation only

  // Local validation: parse and check structure
  try {
    const ext = path.extname(policyPath).toLowerCase();
    let data: any;

    if (ext === ".json") {
      data = JSON.parse(content);
    } else if (ext === ".yaml" || ext === ".yml") {
      try {
        const yaml = require("yaml");
        data = yaml.parse(content);
      } catch (e) {
        throw new FaraCoreError(
          "YAML support requires 'yaml' package. Install with: npm install yaml"
        );
      }
    } else {
      // Try JSON first, then YAML
      try {
        data = JSON.parse(content);
      } catch {
        try {
          const yaml = require("yaml");
          data = yaml.parse(content);
        } catch (e) {
          throw new FaraCoreError(
            "YAML support requires 'yaml' package. Install with: npm install yaml"
          );
        }
      }
    }

    if (typeof data !== "object" || data === null) {
      throw new FaraCorePolicyError("Policy must be a YAML/JSON object");
    }

    // Check for basic structure
    if (!Array.isArray(data.rules)) {
      throw new FaraCorePolicyError("Policy must have 'rules' field as a list");
    }

    // Validate each rule has required fields
    const errors: string[] = [];
    for (let i = 0; i < data.rules.length; i++) {
      const rule = data.rules[i];
      if (typeof rule !== "object" || rule === null) {
        errors.push(`Rule ${i} must be an object`);
        continue;
      }

      if (!rule.match) {
        errors.push(`Rule ${i} missing 'match' field`);
      }

      if (!rule.allow && !rule.deny) {
        errors.push(`Rule ${i} must have 'allow' or 'deny' field`);
      }
    }

    if (errors.length > 0) {
      throw new FaraCorePolicyError(`Policy validation errors: ${errors.join("; ")}`);
    }
  } catch (error: any) {
    if (error instanceof FaraCorePolicyError) {
      throw error;
    }
    throw new FaraCorePolicyError(`Failed to validate policy: ${error.message}`);
  }
}

/**
 * Test a policy against an action (if server endpoint exists)
 */
export async function testPolicyAgainstAction(
  policyPath: string,
  action: any
): Promise<any> {
  if (!fs.existsSync(policyPath)) {
    throw new FaraCoreError(`Policy file not found: ${policyPath}`);
  }

  let policyContent: string;
  try {
    policyContent = fs.readFileSync(policyPath, "utf-8");
  } catch (error: any) {
    throw new FaraCoreError(`Failed to read policy file: ${error.message}`);
  }

  // Try POST to /v1/policy/test if it exists
  // Note: This would require makeRequest to be exported or a dedicated function
  // For now, we'll throw an error indicating the endpoint is not available
  throw new FaraCoreError(
    `Policy testing endpoint not available. Server may not support /v1/policy/test. ` +
    `This feature requires server-side support.`
  );
}
