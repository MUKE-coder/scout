/** The Scout release these docs describe. */
export const SCOUT_VERSION = "0.3.0";
export const RELEASE_URL = `https://github.com/MUKE-coder/scout/releases/tag/v${SCOUT_VERSION}`;
export const REPO_URL = "https://github.com/MUKE-coder/scout";

/**
 * What this release is about, in a few words. Kept here so there is one line to
 * change per release, and the version beside it can never disagree. Both the
 * hero pill and the site banner read it.
 */
export const RELEASE_HEADLINE = "Reachable-CVE scanning, IDOR detection, and more coverage";

/** The banner across the top of every page. Points at what the release added. */
export const RELEASE_BANNER = {
  text: "new checks for reachable Go CVEs, IDOR, version disclosure, directory listing, SRI and mixed content.",
  href: "/reference/checks/",
  label: "See the catalog",
};
