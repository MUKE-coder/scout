// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// This site is fully static — no SSR, so no @astrojs/cloudflare adapter is
// needed. It deploys to Cloudflare as Workers Static Assets (see
// wrangler.jsonc), which serves a plain static build directly.
// https://astro.build/config
export default defineConfig({
  site: "https://scout-docs.codetotech.com",
  integrations: [
    starlight({
      title: "Scout",
      description:
        "Scout is a self-hosted vulnerability scanner and attack-surface mapper for developers. Point it at your app or repo and see every way in.",
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/MUKE-coder/scout" },
      ],
      customCss: ["@fontsource-variable/geist", "@fontsource-variable/geist-mono", "/src/styles/scout-theme.css"],
      favicon: "/favicon.svg",
      // Rich link previews. Starlight sets title/description itself; these are
      // only the image tags it leaves alone.
      head: [
        { tag: "meta", attrs: { property: "og:image", content: "https://scout-docs.codetotech.com/banner-social.png" } },
        { tag: "meta", attrs: { property: "og:image:width", content: "1200" } },
        { tag: "meta", attrs: { property: "og:image:height", content: "630" } },
        { tag: "meta", attrs: { name: "twitter:card", content: "summary_large_image" } },
        { tag: "meta", attrs: { name: "twitter:image", content: "https://scout-docs.codetotech.com/banner-social.png" } },
      ],
      components: {
        SiteTitle: "./src/components/SiteTitle.astro",
        Footer: "./src/components/Footer.astro",
        Banner: "./src/components/Banner.astro",
      },
      logo: {
        src: "./src/assets/scout-mark.svg",
        replacesTitle: false,
      },
      editLink: {
        baseUrl: "https://github.com/MUKE-coder/scout/edit/main/docs-site/",
      },
      sidebar: [
        {
          label: "Start",
          items: [
            { label: "What is Scout?", slug: "index" },
            { label: "Quickstart", slug: "start/quickstart" },
            { label: "Installation", slug: "start/installation" },
            { label: "Modes & environments", slug: "start/modes" },
            { label: "Ownership verification", slug: "start/ownership" },
          ],
        },
        {
          label: "Usage scenarios",
          items: [
            { label: "Scan a running app", slug: "usage/scan-app" },
            { label: "Scan a repo (source)", slug: "usage/scan-repo" },
            { label: "Active scanning", slug: "usage/active" },
            { label: "IDOR & test identities", slug: "usage/idor" },
            { label: "Gate your CI", slug: "usage/ci" },
            { label: "Dashboard & scheduled scans", slug: "usage/dashboard" },
            { label: "Embed in a Go app (Mount)", slug: "usage/library" },
            { label: "Output: JSON, SARIF, reports", slug: "usage/output" },
            { label: "Scan history & diff", slug: "usage/history" },
          ],
        },
        {
          label: "The vuln lab",
          items: [
            { label: "What the lab is", slug: "lab/overview" },
            { label: "Run the lab", slug: "lab/run" },
            { label: "Black-box scan", slug: "lab/black-box" },
            { label: "Source scan", slug: "lab/source" },
            { label: "IDOR on the lab", slug: "lab/idor" },
            { label: "What each check catches", slug: "lab/coverage" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "CLI reference", slug: "reference/cli" },
            { label: "Checks catalog", slug: "reference/checks" },
            { label: "Configuration", slug: "reference/configuration" },
            { label: "Safety model", slug: "reference/safety" },
            { label: "Changelog", slug: "reference/changelog" },
          ],
        },
      ],
    }),
  ],
});
