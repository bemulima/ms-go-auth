#!/usr/bin/env node
'use strict';

// Builds both actual owner implementations before issuing short-lived proofs.
// Keys never leave producer memory; raw proofs use private process pipes only.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const authRoot = path.resolve(__dirname, '..');
let temporaryDirectory;

class ConformanceError extends Error {}

function assert(condition, message) {
  if (!condition) throw new ConformanceError(message);
}

function run(command, args, options, label) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 120000, maxBuffer: 1024 * 1024, ...options });
  // Never echo child output on error: it can contain a raw assertion.
  assert(!result.error && result.status === 0, `${label} failed (child output withheld)`);
  return result.stdout;
}

function main() {
  assert(process.argv.length === 4 && process.argv[2] === '--rbac', 'usage: node scripts/test-mentor-role-conformance.cjs --rbac /absolute/path/to/ms-go-rbac');
  assert(path.isAbsolute(process.argv[3]), 'RBAC checkout path must be absolute');
  const rbacRoot = fs.realpathSync(process.argv[3]);
  assert(/^module github\.com\/example\/ms-rbac-service\s*$/m.test(fs.readFileSync(path.join(rbacRoot, 'go.mod'), 'utf8')), 'unexpected RBAC module');
  const manifest = JSON.parse(fs.readFileSync(path.join(authRoot, '.ai/contracts/mentor-role-decision-v1.json'), 'utf8'));
  const cacheRoot = path.join(authRoot, '.cache');
  fs.mkdirSync(cacheRoot, { recursive: true });
  temporaryDirectory = fs.mkdtempSync(path.join(cacheRoot, 'mentor-wire-conformance-'));
  const producer = path.join(temporaryDirectory, 'producer');
  const consumer = path.join(temporaryDirectory, 'consumer');
  run('go', ['build', '-buildvcs=false', '-tags=mentorconformance', '-o', producer, './test/mentorconformance'], { cwd: authRoot }, 'Auth bridge build');
  run('go', ['build', '-buildvcs=false', '-tags=mentorconformance', '-o', consumer, './test/mentorconformance'], { cwd: rbacRoot }, 'RBAC bridge build');
  const wire = run(producer, [], { cwd: temporaryDirectory }, 'Auth issuer');
  const envelope = JSON.parse(wire);
  assert(Object.keys(envelope.proofs).length === 4, 'expected four real Auth assertions');
  for (const token of Object.values(envelope.proofs)) {
    assert(typeof token === 'string' && token.length <= manifest.max_token_bytes, 'wire size mismatch');
    const parts = token.split('.');
    assert(parts.length === 3, 'compact JWT shape mismatch');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
    assert(JSON.stringify(Object.keys(header).sort()) === JSON.stringify(Object.keys(manifest.header).sort()), 'header field drift');
    for (const [key, value] of Object.entries(manifest.header)) assert(header[key] === value, 'header value drift');
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
    assert(JSON.stringify(Object.keys(claims).sort()) === JSON.stringify([...manifest.required_claims].sort()), 'claim field drift');
    for (const [key, value] of Object.entries(manifest.constants)) assert(claims[key] === value, 'claim constant drift');
    assert(manifest.decisions[claims.decision].includes(claims.application_revision), 'decision/revision drift');
    assert(Number.isSafeInteger(claims.iat) && claims.iat > 0 && Number.isSafeInteger(claims.exp) && claims.exp <= manifest.maximum_integer_time, 'timestamp range drift');
    assert(claims.exp - claims.iat === manifest.producer_ttl_seconds, 'producer TTL drift');
  }
  const result = JSON.parse(run(consumer, [], { cwd: temporaryDirectory, input: wire }, 'RBAC real proof admission'));
  assert(result.status === 'PASS' && result.proofs === 4 && result.checks === 8, 'unexpected consumer report');
  process.stdout.write(JSON.stringify({ status: 'PASS', contract: manifest.contract, proofs: result.proofs, checks: result.checks, cryptography: 'actual Auth issuer -> actual RBAC verifier', owner_ports: 'test doubles', persistent_store: 'not used', runtime: 'not mounted' }) + '\n');
}

try {
  main();
} catch (error) {
  // Only our fixed descriptions are safe: a parser error can quote child data.
  const description = error instanceof ConformanceError ? error.message : 'unexpected setup or wire error (details withheld)';
  process.stderr.write(`mentor conformance: ${description}\n`);
  process.exitCode = 1;
} finally {
  if (temporaryDirectory) fs.rmSync(temporaryDirectory, { recursive: true, force: true });
}
