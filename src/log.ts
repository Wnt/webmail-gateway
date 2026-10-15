import { pino } from "pino";
import type { Config } from "./config.js";

/** JSON logger; credentials never reach the log (request headers are not logged, and these paths are redacted anyway). */
export function createLogger(config: Pick<Config, "logLevel">) {
  return pino({
    level: config.logLevel,
    redact: {
      paths: ["req.headers.authorization", "req.headers.cookie", "*.password", "*.gandiPassword", "*.secret"],
      censor: "[redacted]",
    },
  });
}
