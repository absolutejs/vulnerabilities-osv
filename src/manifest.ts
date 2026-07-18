import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["platform-operators", "security-teams"],
    intents: [
      "query the official OSV API",
      "normalize OSV vulnerability advisories",
      "ingest open source vulnerability intelligence",
    ],
    keywords: ["vulnerabilities", "CVE", "OSV", "advisories"],
    protocols: ["OSV API v1", "OSV schema"],
  },
  identity: {
    accent: "#2563eb",
    category: "operations",
    description:
      "Official OSV API ingestion and normalized advisory records for AbsoluteJS vulnerability management.",
    docsUrl: "https://github.com/absolutejs/vulnerabilities-osv",
    name: "@absolutejs/vulnerabilities-osv",
    tagline: "Bring official OSV intelligence into AbsoluteJS.",
  },
  settings: Type.Object({}),
  wiring: [],
});
