#!/usr/bin/env node
'use strict';

// Offline transport fixture: keys are ephemeral and passed through private
// process pipes only. Production clients and providers perform all cryptography.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');
const { spawn, spawnSync } = require('node:child_process');

class ConformanceError extends Error {}
const assert = (condition, message) => { if (!condition) throw new ConformanceError(message); };
const authRoot = path.resolve(__dirname, '..');
let ownedDirectory;
let authChild;

function run(command, args, options, label) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 120000, maxBuffer: 1024 * 1024, ...options });
  assert(!result.error && result.status === 0, `${label} failed (child output withheld)`);
  return result.stdout;
}

function keyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

async function main() {
  assert(process.argv.length === 6 && process.argv[2] === '--rbac' && process.argv[4] === '--mentor', 'usage: node scripts/test-mentor-owner-conformance.cjs --rbac /absolute/rbac --mentor /absolute/mentor');
  assert(path.isAbsolute(process.argv[3]) && path.isAbsolute(process.argv[5]), 'owner checkout paths must be absolute');
  const rbacRoot = fs.realpathSync(process.argv[3]);
  const mentorRoot = fs.realpathSync(process.argv[5]);
  assert(/^module github\.com\/example\/ms-rbac-service\s*$/m.test(fs.readFileSync(path.join(rbacRoot, 'go.mod'), 'utf8')), 'unexpected RBAC module');
  assert(/^module github\.com\/bemulima\/ms-go-mentor\s*$/m.test(fs.readFileSync(path.join(mentorRoot, 'go.mod'), 'utf8')), 'unexpected Mentor module');
  const manifest = JSON.parse(fs.readFileSync(path.join(authRoot, '.ai/contracts/mentor-owner-lookups-v1.json'), 'utf8'));
  const replies = {
    rbac: JSON.parse(fs.readFileSync(path.join(rbacRoot, '.ai/contracts/mentor-canonical-admin-decision-v1.json'), 'utf8')),
    mentor: JSON.parse(fs.readFileSync(path.join(mentorRoot, '.ai/contracts/mentor-committed-intent-decision-v1.json'), 'utf8')),
  };
  const cacheRoot = path.join(authRoot, '.cache');
  fs.mkdirSync(cacheRoot, { recursive: true });
  ownedDirectory = fs.mkdtempSync(path.join(cacheRoot, 'mentor-owner-conformance-'));
  const binaries = { auth: path.join(ownedDirectory, 'auth'), rbac: path.join(ownedDirectory, 'rbac'), mentor: path.join(ownedDirectory, 'mentor') };
  for (const [owner, cwd] of Object.entries({ auth: authRoot, rbac: rbacRoot, mentor: mentorRoot })) {
    // Test binaries also support source exports and isolated linked worktrees;
    // source identity is verified separately from optional Go VCS stamping.
    run('go', ['build', '-buildvcs=false', '-tags=mentorconformance', '-o', binaries[owner], './test/mentorownerconformance'], { cwd }, `${owner} bridge build`);
  }
  const lookup = keyPair(), rbac = keyPair(), mentor = keyPair();
  const seenNonces = new Set();
  const firstAllowReplies = new Map();
  let summary;
  let grantVerified = false;
  let requests = 0;
  authChild = spawn(binaries.auth, [], { cwd: ownedDirectory, stdio: ['pipe', 'pipe', 'pipe'] });
  // Consume but never display child diagnostics; they might contain proof data.
  authChild.stderr.resume();
  const completion = new Promise((resolve) => {
    authChild.on('error', () => resolve({ code: -1 }));
    authChild.on('close', code => resolve({ code }));
  });
  const timer = setTimeout(() => authChild?.kill('SIGTERM'), 60000);
  try {
    authChild.stdin.write(JSON.stringify({ lookup_private_key: lookup.privateKey, lookup_public_key: lookup.publicKey, rbac_public_key: rbac.publicKey, mentor_public_key: mentor.publicKey }) + '\n');
    const lines = readline.createInterface({ input: authChild.stdout });
    for await (const line of lines) {
      const frame = JSON.parse(line);
      if (frame.kind === 'summary') {
        assert(!summary && frame.status === 'PASS', 'invalid or duplicate driver summary');
        summary = frame;
        continue;
      }
      if (frame.kind === 'grant_verify') {
        const result = JSON.parse(run(binaries.rbac, [], {
          timeout: 2500,
          input: JSON.stringify({ operation: 'verify_role_proof', proof: frame.proof, grant_public_key: frame.public_key }),
        }, 'actual RBAC final proof verification'));
        assert(result.accepted === true && !grantVerified, 'final role proof not accepted exactly once');
        grantVerified = true;
        authChild.stdin.write(JSON.stringify({ accepted: true }) + '\n');
        continue;
      }
      assert(frame.kind === 'rpc' && !summary, 'unexpected test-driver frame');
      requests++;
      const operation = Object.values(manifest.operations).find(op => op.subject === frame.subject);
      assert(operation && frame.body && typeof frame.body.proof === 'string', 'unexpected owner request');
      assert(Object.keys(frame.body).length === 1, 'request envelope drift');
      const claims = JSON.parse(Buffer.from(frame.body.proof.split('.')[1], 'base64url'));
      assert(JSON.stringify(Object.keys(claims).sort()) === JSON.stringify([...operation.request_claims].sort()), 'request claim schema drift');
      for (const [name, value] of Object.entries(operation.constants)) assert(claims[name] === value, 'request constant drift');
      assert(claims.subject === frame.subject && !seenNonces.has(claims.jti), 'wrong subject or reused lookup nonce');
      seenNonces.add(claims.jti);
      const owner = frame.subject === manifest.operations.canonical_admin.subject ? 'rbac' : 'mentor';
      let reply;
      if (frame.mode === 'replay') {
        assert(firstAllowReplies.has(owner), 'missing prior reply fixture');
        reply = firstAllowReplies.get(owner);
        // This negative case must fail on nonce correlation, not merely on
        // expiry in a slow environment. It was accepted with its original key.
        const priorClaims = JSON.parse(Buffer.from(reply.body.decision_jwt.split('.')[1], 'base64url'));
        assert(priorClaims.exp > Math.floor(Date.now() / 1000) + 1, 'cached replay fixture expired before nonce test');
      } else if (frame.mode === 'unsigned') {
        reply = { body: { ok: true } };
      } else {
        const pair = frame.mode === 'wrong_owner_key' ? (owner === 'rbac' ? mentor : rbac) : (owner === 'rbac' ? rbac : mentor);
        reply = JSON.parse(run(binaries[owner], [], {
          timeout: 2500,
          input: JSON.stringify({ operation: 'lookup', mode: frame.mode, subject: frame.subject, body: frame.body,
            lookup_public_key: lookup.publicKey, reply_private_key: pair.privateKey, reply_public_key: pair.publicKey }),
        }, `${owner} actual provider`));
        if (!reply.unavailable) {
          const schema = replies[owner];
          assert(JSON.stringify(Object.keys(reply.body).sort()) === JSON.stringify([...(schema.response_envelope_fields || schema.envelope_fields)].sort()), 'owner reply envelope drift');
          const decoded = JSON.parse(Buffer.from(reply.body.decision_jwt.split('.')[1], 'base64url'));
          assert(JSON.stringify(Object.keys(decoded).sort()) === JSON.stringify([...schema.required_claims].sort()), 'owner reply schema drift');
          for (const [name, value] of Object.entries(schema.constants)) assert(decoded[name] === value, 'owner reply constant drift');
          assert(decoded.sub === claims.sub && decoded.request_jti === claims.jti && decoded.request_digest === crypto.createHash('sha256').update(frame.body.proof).digest('hex'), 'owner reply request-binding drift');
          assert(Number.isSafeInteger(decoded.iat) && Number.isSafeInteger(decoded.exp) && decoded.exp > decoded.iat && decoded.exp - decoded.iat <= schema.maximum_ttl_seconds && decoded.exp <= claims.exp, 'owner reply lifetime drift');
        }
        if (frame.mode === 'normal' && !firstAllowReplies.has(owner) && !reply.unavailable) firstAllowReplies.set(owner, reply);
        if (frame.mode === 'tamper') {
          assert(reply.body?.decision_jwt, 'missing tamper fixture');
          const parts = reply.body.decision_jwt.split('.');
          const signature = Buffer.from(parts[2], 'base64url');
          signature[0] ^= 1;
          parts[2] = signature.toString('base64url');
          reply = { body: { decision_jwt: parts.join('.') } };
        }
      }
      authChild.stdin.write(JSON.stringify(reply) + '\n');
    }
    const done = await completion;
    assert(done.code === 0 && summary?.checks === 17 && summary.requests === requests && grantVerified, 'driver checks failed (child output withheld)');
    process.stdout.write(JSON.stringify({ status: 'PASS', contract: manifest.contract, checks: summary.checks, requests,
      final_role_proof: 'actual Auth issuer -> actual RBAC verifier',
      owner_confirmations: 'actual Auth clients -> actual RBAC/Mentor signed providers',
      transport: 'private-pipe fixture, no live broker', repositories: 'controlled read fixtures, no PostgreSQL', runtime: 'unmounted' }) + '\n');
  } finally {
    clearTimeout(timer);
  }
}

main().catch(error => {
  process.stderr.write(`mentor owner conformance: ${error instanceof ConformanceError ? error.message : 'unexpected setup or protocol error (details withheld)'}\n`);
  process.exitCode = 1;
}).finally(() => {
  if (authChild && authChild.exitCode === null) authChild.kill('SIGTERM');
  if (ownedDirectory) fs.rmSync(ownedDirectory, { recursive: true, force: true });
});
