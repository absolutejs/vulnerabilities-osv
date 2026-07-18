import { describe, expect, test } from "bun:test";
import { createOsvAdapter, normalizeOsvAdvisory, type OsvFetch } from "../src";

const fetchedAt = "2026-07-18T19:00:00Z";
const advisory = {
  affected: [
    {
      package: {
        ecosystem: "npm",
        name: "fixture",
        purl: "pkg:npm/fixture",
      },
      ranges: [
        {
          events: [{ introduced: "0" }, { fixed: "1.2.3" }],
          type: "SEMVER",
        },
      ],
      versions: ["1.0.0", "1.0.0"],
    },
  ],
  aliases: ["CVE-2026-0001"],
  details: "Fixture details",
  id: "GHSA-fixture",
  modified: "2026-07-18T18:30:00Z",
  published: "2026-07-17T18:30:00Z",
  schema_version: "1.7.4",
  severity: [
    { score: "CVSS:3.1/AV:N/AC:L", type: "CVSS_V3" },
    { score: "medium", type: "Ubuntu" },
  ],
  summary: "Fixture advisory",
};

describe("OSV normalization", () => {
  test("preserves aliases, affected ranges, and source provenance", () => {
    const result = normalizeOsvAdvisory(advisory, { fetchedAt });
    expect(result.aliases).toEqual(["GHSA-fixture", "CVE-2026-0001"]);
    expect(result.affected?.[0]?.ranges[0]).toEqual({
      events: [{ introduced: "0" }, { fixed: "1.2.3" }],
      repository: null,
      type: "semver",
    });
    expect(result.affected?.[0]?.versions).toEqual(["1.0.0"]);
    expect(result.severity[0]?.system).toBe("cvss-v3");
    expect(result.severity[1]).toEqual({
      score: null,
      system: "vendor",
      value: "medium",
      vector: "medium",
    });
    expect(result.source).toEqual({
      fetchedAt,
      name: "osv",
      revision: "1.7.4",
      url: "https://api.osv.dev/v1/vulns/GHSA-fixture",
    });
  });

  test("rejects advisories without required identity and timestamps", () => {
    expect(() => normalizeOsvAdvisory({}, { fetchedAt })).toThrow(
      "OSV advisory id",
    );
    expect(() =>
      normalizeOsvAdvisory({ ...advisory, modified: "invalid" }, { fetchedAt }),
    ).toThrow("valid timestamp");
  });
});

describe("OSV adapter", () => {
  test("follows per-query pagination and fetches unique advisories", async () => {
    const requests: Array<{ body?: string; url: string }> = [];
    const fetcher: OsvFetch = async (input, init) => {
      const url = String(input);
      requests.push({
        ...(typeof init?.body === "string" ? { body: init.body } : {}),
        url,
      });
      if (url.endsWith("/querybatch")) {
        const body = JSON.parse(String(init?.body)) as {
          queries: Array<{ page_token?: string }>;
        };
        return Response.json({
          results: body.queries.map((query) =>
            query.page_token
              ? { vulns: [{ id: "GHSA-second" }] }
              : {
                  next_page_token: "page-2",
                  vulns: [{ id: "GHSA-fixture" }],
                },
          ),
        });
      }
      const id = decodeURIComponent(url.split("/").at(-1) ?? "");
      return Response.json({ ...advisory, id });
    };
    const adapter = createOsvAdapter({
      fetch: fetcher,
      queries: [
        { package: { ecosystem: "npm", name: "fixture" }, version: "1.0.0" },
      ],
    });

    const result = await adapter.fetch({ cursor: null });
    expect(result.status).toBe("updated");
    if (result.status !== "updated") throw new Error("Expected update");
    expect(result.records.map(({ id }) => id)).toEqual([
      "GHSA-fixture",
      "GHSA-second",
    ]);
    expect(
      requests.filter(({ url }) => url.endsWith("/querybatch")),
    ).toHaveLength(2);
    expect(requests[1]?.body).toContain('"page_token":"page-2"');
  });

  test("fails closed when batch results do not align with queries", async () => {
    const adapter = createOsvAdapter({
      fetch: async () => Response.json({ results: [] }),
      queries: [{ commit: "abc" }],
    });
    expect(adapter.fetch({ cursor: null })).rejects.toThrow("misaligned");
  });
});
