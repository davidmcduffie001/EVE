import { describe, expect, it } from "vitest";

import viteConfig from "../vite.config";

describe("vite dev server", () => {
  it("uses port 8000 for local UI review", () => {
    expect(viteConfig.server?.port).toBe(8000);
  });
});
