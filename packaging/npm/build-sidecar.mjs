#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, rmSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const { values } = parseArgs({
  options: {
    'x64-binary': { type: 'string' },
    'arm64-binary': { type: 'string' },
    'out-dir': { type: 'string' },
    'version': { type: 'string' },
  },
});

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..', '..');

const x64Binary = values['x64-binary'] ?? join(repoRoot, 'target', 'x86_64-pc-windows-msvc', 'release', 'msixbundle-cli.exe');
const arm64Binary = values['arm64-binary'] ?? join(repoRoot, 'target', 'aarch64-pc-windows-msvc', 'release', 'msixbundle-cli.exe');
const outDir = values['out-dir'] ?? join(here, 'dist');
const version = values.version ?? readWorkspaceVersion();

for (const [label, p] of [['x64', x64Binary], ['arm64', arm64Binary]]) {
  if (!existsSync(p)) {
    console.error(`Missing ${label} binary: ${p}`);
    process.exit(1);
  }
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(join(outDir, 'bin', 'x64'), { recursive: true });
mkdirSync(join(outDir, 'bin', 'arm64'), { recursive: true });

copyFileSync(x64Binary, join(outDir, 'bin', 'x64', 'msixbundle-cli.exe'));
copyFileSync(arm64Binary, join(outDir, 'bin', 'arm64', 'msixbundle-cli.exe'));

const pkg = {
  name: '@choochmeque/msixbundle-cli-win32',
  version,
  description: 'Prebuilt Windows binaries for msixbundle-cli (x64 + arm64). Consumed as an optional sidecar by @choochmeque/tauri-windows-bundle.',
  os: ['win32'],
  license: 'MIT',
  repository: {
    type: 'git',
    url: 'https://github.com/Choochmeque/msixbundle-rs',
  },
  homepage: 'https://github.com/Choochmeque/msixbundle-rs',
  files: ['bin/', 'README.md'],
  publishConfig: { access: 'public' },
};

writeFileSync(join(outDir, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
copyFileSync(join(here, 'README.md'), join(outDir, 'README.md'));

console.log(`Sidecar package built at ${outDir} (version ${version})`);

function readWorkspaceVersion() {
  const cargoToml = readFileSync(join(repoRoot, 'Cargo.toml'), 'utf8');
  const match = cargoToml.match(/^\s*version\s*=\s*"([^"]+)"/m);
  if (!match) {
    console.error('Could not read version from workspace Cargo.toml');
    process.exit(1);
  }
  return match[1];
}
