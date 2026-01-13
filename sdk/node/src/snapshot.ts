/**
 * In-memory action snapshot store for convenience
 */

import { Action } from "./types";

export class ActionSnapshotStore {
  private actions: Map<string, Action> = new Map();
  private recent: string[] = [];
  private maxSize: number;

  constructor(maxSize: number = 1000) {
    this.maxSize = maxSize;
  }

  addAction(action: Action): void {
    const actionId = action.id;
    if (!actionId) {
      throw new Error("Action must have 'id' field");
    }

    this.actions.set(actionId, action);
    this.recent.push(actionId);

    // Trim if over max size
    if (this.recent.length > this.maxSize) {
      const removed = this.recent.shift();
      if (removed) {
        this.actions.delete(removed);
      }
    }
  }

  getAction(actionId: string): Action | undefined {
    return this.actions.get(actionId);
  }

  listRecent(limit: number = 50): Action[] {
    const recentIds = this.recent.slice(-limit);
    return recentIds
      .reverse()
      .map((id) => this.actions.get(id))
      .filter((action): action is Action => action !== undefined);
  }

  clear(): void {
    this.actions.clear();
    this.recent = [];
  }
}

// Optional singleton instance
let defaultStore: ActionSnapshotStore | null = null;

export function getDefaultStore(): ActionSnapshotStore {
  if (!defaultStore) {
    defaultStore = new ActionSnapshotStore();
  }
  return defaultStore;
}
