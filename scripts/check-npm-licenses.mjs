#!/usr/bin/env node
// CI license gate for the frontend's npm production dependency tree.
//
// Reads a CycloneDX SBOM produced by `@cyclonedx/cyclonedx-npm --omit dev`
// and fails (exit 1) if any component's license isn't in ALLOWED_LICENSES
// below. The allowlist mirrors docs/THIRD_PARTY_LICENSES.md's npm section
// exactly — update both together, never just one, or they will silently
// drift out of sync (the exact failure mode this whole phase exists to
// close). No GPL/LGPL/AGPL license is on this list; if one shows up in a
// future dependency, this gate is the thing that catches it.

import { readFileSync } from 'node:fs';

const ALLOWED_LICENSES = new Set([
  '0BSD',
  'Apache-2.0',
  'BSD-3-Clause',
  'ISC',
  'MIT',
  'MIT AND ISC',
  'OFL-1.1',
]);

const sbomPath = process.argv[2];
if (!sbomPath) {
  console.error('usage: check-npm-licenses.mjs <cyclonedx-sbom.json>');
  process.exit(2);
}

const sbom = JSON.parse(readFileSync(sbomPath, 'utf-8'));
const components = sbom.components ?? [];

if (components.length === 0) {
  console.error('No components found in SBOM — refusing to pass an empty scan silently.');
  process.exit(2);
}

const offenders = [];
for (const c of components) {
  const licenseIds = (c.licenses ?? [])
    .map((l) => (l.license ? l.license.id ?? l.license.name : l.expression))
    .filter(Boolean);

  if (licenseIds.length === 0) {
    offenders.push({ name: c.name, version: c.version, license: 'UNKNOWN (no license metadata)' });
    continue;
  }

  const disallowed = licenseIds.filter((id) => !ALLOWED_LICENSES.has(id));
  if (disallowed.length > 0) {
    offenders.push({ name: c.name, version: c.version, license: disallowed.join('; ') });
  }
}

if (offenders.length > 0) {
  console.error(`License gate FAILED — ${offenders.length} package(s) with a disallowed or missing license:\n`);
  for (const o of offenders) {
    console.error(`  ${o.name}@${o.version}: ${o.license}`);
  }
  console.error(
    '\nIf this license is genuinely acceptable, add it to ALLOWED_LICENSES in this ' +
      'script AND to docs/THIRD_PARTY_LICENSES.md\'s npm section, with the reasoning ' +
      'documented the same way pyphen and certifi are in that file\'s Copyleft section.'
  );
  process.exit(1);
}

console.log(`License gate passed — ${components.length} npm production package(s), all within the allowlist.`);
process.exit(0);
