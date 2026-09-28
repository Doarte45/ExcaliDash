import { describe, it, expect } from "vitest";
import { sanitizeSvg } from "../security";

// B12: the dashboard preview sanitizer must keep S3-mode image hrefs so
// thumbnails don't lose every image. It accepts svg+xml data URLs and
// same-origin `/api/files/...` references in addition to raster data URLs,
// while still stripping dangerous hrefs.
describe("sanitizeSvg preview image hrefs (S3 rehydration)", () => {
  const wrap = (image: string): string =>
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">${image}</svg>`;

  it("preserves an svg+xml base64 data URL image", () => {
    const href = "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=";
    const out = sanitizeSvg(
      wrap(`<image x="0" y="0" width="100" height="100" href="${href}" />`),
    );
    expect(out).toContain("<image");
    expect(out).toContain(href);
  });

  it("preserves a same-origin /api/files reference", () => {
    const href = "/api/files/drawing_1/file_abc";
    const out = sanitizeSvg(
      wrap(`<image x="0" y="0" width="100" height="100" href="${href}" />`),
    );
    expect(out).toContain("<image");
    expect(out).toContain(href);
  });

  it("still preserves a raster png data URL", () => {
    const href =
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    const out = sanitizeSvg(
      wrap(`<image x="0" y="0" width="1" height="1" href="${href}" />`),
    );
    expect(out).toContain(href);
  });

  it("strips a javascript: href", () => {
    const out = sanitizeSvg(
      wrap(
        `<image x="0" y="0" width="1" height="1" href="javascript:alert(1)" />`,
      ),
    );
    expect(out).not.toContain("javascript:");
    expect(out).not.toContain("<image");
  });

  it("strips an arbitrary cross-path url that is not a file reference", () => {
    const out = sanitizeSvg(
      wrap(`<image x="0" y="0" width="1" height="1" href="/etc/passwd" />`),
    );
    expect(out).not.toContain("/etc/passwd");
    expect(out).not.toContain("<image");
  });
});

// Excalidraw 0.18 exports labeled arrows through <mask>, images through
// <symbol>/<use>, and rounded images through <clipPath>. Stripping those
// wrappers while keeping their children leaves the mask rects drawn as solid
// shapes (black blocks in dark mode) and strands images inside <defs>.
describe("sanitizeSvg preview references (masks, symbols, clip paths)", () => {
  const wrap = (content: string): string =>
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 300">${content}</svg>`;

  it("keeps a labeled arrow's mask and its reference", () => {
    const out = sanitizeSvg(
      wrap(
        '<g mask="url(#mask-arrow1)" stroke-linecap="round"><path d="M0 0 L100 100" stroke="#1e1e1e" fill="none"></path></g>' +
          '<mask id="mask-arrow1"><rect x="0" y="0" fill="#fff" width="210" height="210"></rect><rect x="40" y="40" fill="#000" width="60" height="25" opacity="1"></rect></mask>',
      ),
    );
    expect(out).toContain('mask="url(#mask-arrow1)"');
    expect(out).toMatch(
      /<mask id="mask-arrow1"><rect[^>]*fill="#fff"[^>]*><\/rect><rect[^>]*fill="#000"[^>]*><\/rect><\/mask>/,
    );
  });

  it("keeps image symbols and the <use> elements that place them", () => {
    const out = sanitizeSvg(
      wrap(
        '<defs><symbol id="image-abc123"><image href="/api/files/drawing_1/abc123" preserveAspectRatio="none" width="100%" height="100%"></image></symbol></defs>' +
          '<g transform="translate(10 10)"><use href="#image-abc123" width="100" height="100" opacity="1"></use></g>',
      ),
    );
    expect(out).toMatch(
      /<symbol id="image-abc123"><image href="\/api\/files\/drawing_1\/abc123"/,
    );
    expect(out).toContain('<use href="#image-abc123" width="100" height="100"');
  });

  it("keeps a rounded image clip path and its reference", () => {
    const out = sanitizeSvg(
      wrap(
        '<clipPath id="image-clipPath-el1"><rect width="100" height="100" rx="8" ry="8"></rect></clipPath>' +
          '<g clip-path="url(#image-clipPath-el1)"><use href="#image-abc123" width="100" height="100"></use></g>',
      ),
    );
    expect(out).toMatch(/<clipPath id="image-clipPath-el1"><rect/);
    expect(out).toContain('clip-path="url(#image-clipPath-el1)"');
  });

  it.each([
    "https://evil.example/sprite.svg#icon",
    "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
    "javascript:alert(1)",
  ])("drops a <use> href that is not a local fragment: %s", (href) => {
    const out = sanitizeSvg(
      wrap(
        `<use href="${href}" width="10" height="10"></use><use xlink:href="${href}" width="10" height="10"></use>`,
      ),
    );
    expect(out).not.toContain(href);
    expect(out).not.toMatch(/<use[^>]*href/);
  });

  it.each(["mask", "clip-path"])(
    "drops a %s attribute that points outside the preview",
    (attribute) => {
      const out = sanitizeSvg(
        wrap(
          `<g ${attribute}="url(https://evil.example/m.svg#m)"><path d="M0 0"></path></g>` +
            `<g ${attribute}="url(javascript:alert(1))"><path d="M0 0"></path></g>`,
        ),
      );
      expect(out).not.toContain("evil.example");
      expect(out).not.toContain("javascript:");
      expect(out).not.toContain(`${attribute}=`);
    },
  );

  it("still strips scripts nested inside allowed containers", () => {
    const out = sanitizeSvg(
      wrap(
        '<symbol id="s"><script>alert(1)</script></symbol><mask id="m"><foreignObject><div>x</div></foreignObject></mask>',
      ),
    );
    expect(out).not.toContain("<script");
    expect(out).not.toContain("alert(1)");
    expect(out).not.toContain("foreignObject");
  });
});
