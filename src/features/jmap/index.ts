import type { CliCommand, FeaturePlugin } from "../../types.js";

/**
 * jmap feature plugin. SKELETON NO-OP: registers no routes and does nothing.
 * The jmap agent replaces this body (keep the export name).
 */
export const jmapPlugin: FeaturePlugin = async () => {
  // intentionally empty
};

/** CLI commands contributed by this feature (merged into `src/cli.ts`). */
export const jmapCliCommands: Record<string, CliCommand> = {};
