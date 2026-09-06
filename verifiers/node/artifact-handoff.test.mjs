import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdtempSync, cpSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HandoffError, parseStrictJSON, signedBytes, verifyHandoff, verifyDirectory, runCorpus } from './artifact-handoff.mjs';

const corpusPath = fileURLToPath(new URL('../../examples/artifact-handoff-v0.1/', import.meta.url));
const verifierPath = fileURLToPath(new URL('./artifact-handoff.mjs', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value));
function bundle() {
  const path = join(corpusPath, 'packages/p001');
  return { files: Object.fromEntries(readdirSync(path).map(name => [name, readFileSync(join(path, name))])),
    context: JSON.parse(readFileSync(join(corpusPath, 'contexts/matching.json'))) };
}
function refresh(files) {
  const manifest = JSON.parse(files['manifest.json']);
  manifest.files = Object.fromEntries(Object.entries(files).filter(([name]) => name !== 'manifest.json')
    .map(([name, bytes]) => [name, { bytes: bytes.length, sha256: sha(bytes) }]));
  files['manifest.json'] = encode(manifest);
}
function rejects(call, code) { assert.throws(call, error => error instanceof HandoffError && error.code === code); }

for (const [name, raw, code] of [
  ['duplicate key', '{"a":1,"a":2}', 'duplicate-json-key'],
  ['escaped duplicate key', '{"a":1,"\\u0061":2}', 'duplicate-json-key'],
  ['nested duplicate', '{"a":{"b":1,"b":2}}', 'duplicate-json-key'],
  ['fraction', '{"a":1.0}', 'invalid-number'],
  ['exponent', '{"a":1e0}', 'invalid-number'],
  ['nonfinite', '{"a":NaN}', 'invalid-number'],
  ['infinity', '{"a":Infinity}', 'invalid-number'],
  ['negative', '{"a":-1}', 'invalid-integer'],
  ['unsafe integer', '{"a":9007199254740992}', 'invalid-integer'],
  ['leading zero', '{"a":01}', 'invalid-json'],
  ['trailing comma', '{"a":1,}', 'invalid-json'],
  ['trailing array comma', '[1,]', 'invalid-json'],
  ['extra document', '{} {}', 'invalid-json'],
  ['non-JSON whitespace', '\u00a0{}', 'invalid-json'],
  ['literal control', '{"a":"\n"}', 'invalid-json'],
  ['bad escape', '{"a":"\\q"}', 'invalid-json'],
  ['UTF8 BOM', Buffer.from([239,187,191,123,125]), 'invalid-json'],
  ['invalid UTF8', Buffer.from([123,34,97,34,58,34,255,34,125]), 'invalid-json'],
  ['deep input', '['.repeat(13) + '0' + ']'.repeat(13), 'input-limit'],
  ['metadata limit', Buffer.alloc(131073, 32), 'input-limit'],
]) test('strict JSON: ' + name, () => rejects(() => parseStrictJSON(Buffer.isBuffer(raw) ? raw : Buffer.from(raw)), code));

test('JSON boundary and decoded object members are preserved without prototypes', () => {
  const parsed = parseStrictJSON(Buffer.from('{"__proto__":{"x":1},"constructor":2,"n":9007199254740991,"b":true}'));
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal(parsed.__proto__.x, 1); assert.equal(parsed.constructor, 2);
  assert.equal(parsed.n, 9007199254740991); assert.equal(parsed.b, true);
  assert.doesNotThrow(() => parseStrictJSON(Buffer.from('['.repeat(12) + '0' + ']'.repeat(12))));
});

for (const [name, mutate, code] of [
  ['boolean epoch', c => { c.historical_policies[0].epoch = true; }, 'invalid-integer'],
  ['unknown field', c => { c.extra = 1; }, 'invalid-fields'],
  ['unknown schema', c => { c.schema += '-other'; }, 'unsupported-schema'],
  ['trailing newline identifier', c => { c.expected.correlation_id += '\n'; }, 'invalid-identifier'],
  ['uppercase digest', c => { c.expected.artifact_sha256 = c.expected.artifact_sha256.toUpperCase(); }, 'invalid-hex'],
  ['invalid finality type', c => { c.expected.snapshots_final_at_cutoff = 1; }, 'invalid-boolean'],
  ['duplicate archive', c => { c.historical_policies.push(c.historical_policies[0]); }, 'ambiguous-policy'],
  ['archive bound', c => { c.historical_policies = Array(17).fill(c.historical_policies[0]); }, 'input-limit'],
  ['observation bound', c => { c.observations.push(c.observations[0]); }, 'input-limit'],
  ['duplicate observation', c => { c.observations[1] = c.observations[0]; }, 'ambiguous-observation'],
  ['epoch body conflict', c => { c.current_policy.valid_until_ms++; }, 'policy-epoch-conflict'],
  ['empty interval', c => { c.current_policy.next_update_ms = c.current_policy.as_of_ms; }, 'invalid-interval'],
]) test('context: ' + name, () => {
  const { files, context } = bundle(); mutate(context);
  rejects(() => verifyHandoff(files, encode(context)), code);
});

test('matching native signatures and whole committed report', () => {
  const { files, context } = bundle();
  const rawContext = readFileSync(join(corpusPath, 'contexts/matching.json'));
  const report = verifyHandoff(files, rawContext);
  const golden = JSON.parse(readFileSync(new URL('../../docs/artifact-handoff-report.json', import.meta.url)));
  assert.deepEqual(JSON.parse(JSON.stringify(report)), golden);
  assert.equal(report.receipts.sender.signature, 'valid');
  assert.equal(report.receipts.receiver.signature, 'valid');
  assert.equal(verifyHandoff(files, encode(context)).handoff_at_cutoff, 'supported-under-receiver-context');
});

test('signed bytes have the fixed native field order and sorted params', () => {
  assert.equal(signedBytes({ step_id: 's', action_id: 'a', params: { z: 2, a: 1 }, success: true, ts_ms: 3, seq: 0 }).toString(),
    '{"step_id":"s","action_id":"a","params":{"a":1,"z":2},"success":true,"ts_ms":3,"seq":0}');
});

test('altered signed member cannot become an authenticated conflict', () => {
  const { files, context } = bundle();
  const oldDigest = sha(files['sender.jsonl']);
  const receipt = JSON.parse(files['sender.jsonl']); receipt.params.artifact_sha256 = '0'.repeat(64);
  files['sender.jsonl'] = Buffer.concat([encode(receipt), Buffer.from('\n')]); refresh(files);
  context.observations.find(o => o.receipt_sha256 === oldDigest).receipt_sha256 = sha(files['sender.jsonl']);
  const report = verifyHandoff(files, encode(context));
  assert.equal(report.receipts.sender.signature, 'invalid');
  assert.equal(report.cross_source.status, 'insufficient-authenticated-projection');
  assert.equal(report.handoff_at_cutoff, 'insufficient-evidence');
});

for (const ending of ['\r\n', '\n\n', '']) test('receipt line ending ' + JSON.stringify(ending), () => {
  const { files, context } = bundle();
  files['sender.jsonl'] = Buffer.from(files['sender.jsonl'].toString().trimEnd() + ending); refresh(files);
  rejects(() => verifyHandoff(files, encode(context)), 'invalid-receipt-line');
});

test('bounded byte API rejects unsupported files and invalid representations', () => {
  const { files, context } = bundle();
  rejects(() => verifyHandoff({ ...files, extra: Buffer.from('x') }, encode(context)), 'invalid-package-files');
  rejects(() => verifyHandoff({ ...files, 'artifact.bin': 'text' }, encode(context)), 'invalid-bytes');
  files['artifact.bin'] = Buffer.alloc(1048577); refresh(files);
  rejects(() => verifyHandoff(files, encode(context)), 'invalid-integer');
});

test('all declared corpus expectations pass', () => {
  const result = runCorpus(corpusPath);
  assert.equal(result.case_count, 40); assert.equal(result.agree_count, 40);
  assert.equal(new Set(result.cases.map(c => c.id)).size, 40);
});

for (const [context, conclusion] of [['matching', 'supported-under-receiver-context'], ['revoked-at-observation', 'insufficient-evidence']]) {
  test('CLI evaluation is not generic approval: ' + context, () => {
    const result = spawnSync(process.execPath, [verifierPath, 'verify', join(corpusPath, 'packages/p001'),
      '--receiver-context', join(corpusPath, 'contexts/' + context + '.json')], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).handoff_at_cutoff, conclusion);
  });
}
for (const [args, code] of [[[], 'invalid-arguments'], [['verify', 'missing-package', '--receiver-context', 'missing-context'], 'input-unavailable']]) {
  test('CLI typed failure: ' + code, () => {
    const result = spawnSync(process.execPath, [verifierPath, ...args], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 2, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.status, 'invalid-input'); assert.equal(output.error.code, code);
    assert.equal(result.stderr, '');
  });
}

function temporary(t) {
  const root = mkdtempSync(join(process.env.TTRACE_TEST_TMP || tmpdir(), 'ttrace-node-test-'));
  t.after(() => rmSync(root, { recursive: true })); return root;
}
test('filesystem checks separate context, unexpected paths and oversize reads', t => {
  const root = temporary(t); const pkg = join(root, 'package');
  cpSync(join(corpusPath, 'packages/p001'), pkg, { recursive: true });
  const context = join(root, 'context.json'); cpSync(join(corpusPath, 'contexts/matching.json'), context);
  assert.equal(verifyDirectory(pkg, context).handoff_at_cutoff, 'supported-under-receiver-context');
  rejects(() => verifyDirectory(pkg, join(pkg, 'manifest.json')), 'self-supplied-context');
  writeFileSync(join(pkg, 'artifact.bin'), Buffer.alloc(1048577));
  rejects(() => verifyDirectory(pkg, context), 'input-limit');
  writeFileSync(join(pkg, 'extra.txt'), 'x');
  rejects(() => verifyDirectory(pkg, context), 'invalid-package-files');
});

test('package file symlinks are rejected', t => {
  const root = temporary(t), pkg = join(root, 'package');
  cpSync(join(corpusPath, 'packages/p001'), pkg, { recursive: true });
  const artifact = join(pkg, 'artifact.bin'); rmSync(artifact);
  try { symlinkSync(join(corpusPath, 'packages/p001/artifact.bin'), artifact); }
  catch (error) { if (error.code === 'EPERM') { t.skip('Windows requires symlink creation privilege'); return; } throw error; }
  rejects(() => verifyDirectory(pkg, join(corpusPath, 'contexts/matching.json')), 'invalid-filesystem-entry');
});

test('empty, duplicated or escaping corpus cannot report full agreement', t => {
  const root = temporary(t); cpSync(corpusPath, root, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(root, 'corpus.json')));
  writeFileSync(join(root, 'corpus.json'), encode({ ...manifest, cases: [] }));
  rejects(() => runCorpus(root), 'invalid-corpus');
  writeFileSync(join(root, 'corpus.json'), encode({ ...manifest, cases: [manifest.cases[0], manifest.cases[0]] }));
  rejects(() => runCorpus(root), 'invalid-corpus');
  manifest.cases[0].package = join(corpusPath, 'packages/p001');
  writeFileSync(join(root, 'corpus.json'), encode(manifest));
  rejects(() => runCorpus(root), 'invalid-corpus');
});
