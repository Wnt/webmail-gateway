import type { CliCommand, FeaturePlugin } from "../../types.js";

/**
 * auth feature plugin. SKELETON NO-OP: registers no routes and does nothing.
 * The auth agent replaces this body (keep the export name).
 */
export const authPlugin: FeaturePlugin = async () => {
  // intentionally empty
};

/** CLI commands contributed by this feature (merged into `src/cli.ts`). */
export const authCliCommands: Record<string, CliCommand> = {};
