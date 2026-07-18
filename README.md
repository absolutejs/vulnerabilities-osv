# @absolutejs/vulnerabilities-osv

Official OSV API ingestion for `@absolutejs/vulnerabilities`. The package
normalizes OSV records into the shared advisory contract, preserves aliases,
affected package ranges, CVSS vectors, and source provenance, and follows
per-query pagination from the OSV batch API.

```ts
import { createOsvAdapter } from "@absolutejs/vulnerabilities-osv";
import { createMemoryFeedStore, syncFeed } from "@absolutejs/vulnerabilities";

const adapter = createOsvAdapter({
  queries: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      version: "4.17.20",
    },
  ],
});

const result = await syncFeed({
  adapter,
  maxStaleMs: 24 * 60 * 60 * 1_000,
  store: createMemoryFeedStore(),
});
```

Each batch result remains aligned with its source query. Pagination tokens are
followed independently, advisory identifiers are deduplicated, and each full
record is retrieved from the official OSV API before normalization.
