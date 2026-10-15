import type { CliCommand, FeaturePlugin } from "../../types.js";

/**
 * push feature plugin. SKELETON NO-OP: registers no routes and does nothing.
 * The push agent replaces this body (keep the export name).
 */
export const pushPlugin: FeaturePlugin = async () => {
  // intentionally empty
};

/** CLI commands contributed by this feature (merged into `src/cli.ts`). */
export const pushCliCommands: Record<string, CliCommand> = {};
