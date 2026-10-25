# CVE Atlas

CVE Atlas is a lightweight vulnerability research workspace. Look up a CVE by ID, or search for a product, organization, or domain to find related NVD records and public reporting.

> A vibe-coded side project I started while busy with other things—the idea was too interesting to leave alone.

The app is built with React, TypeScript, and Vite. It reads public data directly from NVD and GDELT; there is no application server or API key to configure.

## Features

- **CVE lookup:** View the vulnerability summary, publication and update dates, reporting source, CVSS assessment, affected products and versions, weakness classifications, and references when these are available in NVD.
- **Site and product search:** Search NVD by keyword and browse the 20 newest matching CVE records. Selecting a result opens its full report.
- **Public reporting:** Search GDELT news coverage from the past six months for the same term. News articles can cover disclosures that do not have a CVE record.
- **Recent lookups:** Keep a short list of recent CVE IDs in the current browser. This history stays in local storage on that device.
- **Shareable searches:** CVE and site searches are reflected in the URL as `?cve=...` or `?site=...`.
- **Responsive layout:** Use the research workspace on desktop, tablet, and mobile screens.

## Data and interpretation

CVE Atlas presents source material for research. It does not scan websites, confirm exploitability, or determine where a vulnerability was discovered or attempted.

- An NVD keyword match means the record matched the search term. It does not prove the vulnerability was found or exploited on that domain.
- A news article is a research lead. Its claims should be checked against the publisher, affected organization, and any linked technical advisory.
- A reporting source in a CVE record may be an organization or mailbox, not the individual researcher.
- Discovery domains are shown as unknown unless a source explicitly identifies them. Reference hostnames are shown separately and are not treated as discovery locations.
- NVD and GDELT are public services and can rate-limit requests or be temporarily unavailable. When broader coverage is unavailable, use the Google or Bing links shown in site-search results.

## Requirements

- Node.js `20.19+` or `22.12+`
- npm

## Run locally

```sh
npm install
npm run dev
```

Run these commands from the repository root, then open the local URL printed by Vite. No environment variables or API keys are required.

## Deploy to Cloudflare Pages

Connect this GitHub repository to Cloudflare Pages and use these build settings:

| Setting | Value |
| --- | --- |
| Production branch | `main` |
| Framework preset | `Vite` |
| Build command | `npm run build` |
| Build output directory | `dist` |

Vite copies files from `public/` into the root of `dist/`. The included `public/404.html` becomes `dist/404.html`, so Cloudflare Pages can show the custom page when someone opens an unknown URL. CVE Atlas uses query-string searches (such as `/?cve=CVE-2021-44228`), which continue to work from the home page. If client-side routes are added later, configure their fallback behavior alongside the custom 404 page.

## Available scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the Vite development server. |
| `npm run build` | Type-check and create the production build in `dist/`. |
| `npm run preview` | Preview the production build locally. Run `npm run build` first. |
| `npm run lint` | Run Oxlint. |

## Data sources

- [National Vulnerability Database (NVD) CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) — CVE records and keyword results.
- [GDELT DOC 2.0 API](https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/) — public news article search.

## Project structure

```text
src/
  App.tsx       Search flows, API calls, and CVE report components
  App.css       Workspace layout and component styling
  index.css     Global styles and design tokens
public/         Static assets and the editable Cloudflare Pages 404 page
```

## License

No license file is included yet. Add a `LICENSE` file before granting permission to reuse or redistribute this project.
