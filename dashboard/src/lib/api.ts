import createClient from "openapi-fetch";
import type { paths as ThreatIntelPaths } from "../generated/threat-intel";

/**
 * Typed client for the Global Threat Intelligence backend, generated
 * against services/threat-intel's own OpenAPI schema (see
 * src/generated/threat-intel.ts + package.json's "gen:threat-intel" script).
 * Base URL is same-origin in both dev (Vite proxy) and prod (nginx)
 */
export const threatIntelApi = createClient<ThreatIntelPaths>({ baseUrl: "/" });

/**
 * globe/server.py has no OpenAPI schema to generate from (it's the
 * pre-existing Sandbox Lab control API, untouched per Architecture
 * Decision #3). Its typed client arrives in Stage H alongside the ported
 * Sandbox Lab page -- src/lib/sandboxApi.ts is an approved extension
 * point, not built here.
 */
