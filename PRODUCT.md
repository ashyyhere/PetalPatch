# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React with Vite

## Users

People looking up publicly available CVE records.

## Product Purpose

Accept a CVE identifier or a site, domain, or product search term. Show a clear summary of a selected public vulnerability record, including its description, reporting source, publication date, severity, affected products, and references.

## Capabilities and Constraints

- Retrieve public CVE information from the National Vulnerability Database (NVD).
- Search NVD keyword-indexed CVE records for a supplied site, domain, or product term and show a bounded set of matching results.
- Search a separate public news index for reporting on the same term, including disclosures that may not have a CVE record.
- Describe keyword results as mentions or matches; they do not confirm a vulnerability was discovered, attempted, or exploited on a searched domain.
- Treat news coverage as a research lead, show its publisher and date, and do not present allegations as verified technical facts.
- Make the reporting source and record publication date visible when the source provides them.
- Show affected products and versions when available.
- Surface only CVE references that NVD tags as exploit or vendor/advisory sources for reproduction research; label them as unverified links and never generate unsupported CVE-specific steps.
- Frame reproduction guidance around matching an affected version in a disposable, isolated lab and following the linked source's own validation steps.
- Exact discovery or attempted-attack domains are not reliably part of a CVE record. Do not infer them from the affected product; label this information unavailable unless a cited source explicitly provides it.
- Display data provenance and link to the authoritative source record.

## Evidence on Hand

No customer records, private vulnerability data, or brand assets were provided. Use public source data only; do not invent missing fields.

## Product Principles

- Put the CVE identifier and concise description first.
- Keep dates, source attribution, severity, and affected products easy to scan.
- Distinguish source facts from missing or inferred information.
- Link back to the source for verification.
