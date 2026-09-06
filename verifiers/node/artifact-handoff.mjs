// Standalone selected-profile verifier. Only Node built-ins are imported.
// No Python/T-Trace implementation is loaded or invoked.
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { openSync, closeSync, readSync, fstatSync, lstatSync, realpathSync, opendirSync } from 'node:fs';
import { resolve, relative, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROFILE = 'ttrace.artifact-handoff/v1';
export const REPORT_SCHEMA = 'ttrace.artifact-handoff-report/v1';
const PACKAGE_SCHEMA = 'ttrace.artifact-handoff-package/v1';
const CONTEXT_SCHEMA = 'ttrace.handoff-receiver-context/v1';
const ROLES = ['sender', 'receiver'];
const LIMITS = Object.freeze({ 'manifest.json': 131072, 'artifact.bin': 1048576, 'sender.jsonl': 16384, 'receiver.jsonl': 16384 });
const TIME_MAX = 4102444800000;
const POLICY_KEYS = ['epoch', 'valid_from_ms', 'valid_until_ms', 'roles'];
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value);
const sha = raw => createHash('sha256').update(raw).digest('hex');

export class HandoffError extends Error {
  constructor(code, message = code) { super(message); this.name = 'HandoffError'; this.code = code; }
}
const requireValue = (condition, code, message) => { if (!condition) throw new HandoffError(code, message); };

// A lexical parser preserves integer syntax and rejects duplicate decoded keys.
// JSON.parse is used only for an already delimited string literal, never objects.
export function parseStrictJSON(raw, maximum = 131072) {
  requireValue(Buffer.isBuffer(raw) && raw.length <= maximum, 'input-limit');
  let text;
  try {
    requireValue(!(raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf), 'invalid-json');
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch (error) {
    if (error instanceof HandoffError) throw error;
    throw new HandoffError('invalid-json');
  }
  let cursor = 0;
  const whitespace = () => { while (cursor < text.length && ' \t\r\n'.includes(text[cursor])) cursor++; };
  function string() {
    requireValue(text[cursor] === '"', 'invalid-json');
    const start = cursor++;
    while (cursor < text.length) {
      const char = text[cursor++];
      if (char === '"') {
        try { return JSON.parse(text.slice(start, cursor)); }
        catch { throw new HandoffError('invalid-json'); }
      }
      if (char === '\\') cursor++;
      else requireValue(char.charCodeAt(0) >= 32, 'invalid-json');
    }
    throw new HandoffError('invalid-json');
  }
  function value(depth) {
    requireValue(depth <= 12, 'input-limit');
    whitespace();
    const char = text[cursor];
    if (char === '"') return string();
    if (char === '{') {
      cursor++; whitespace();
      const pairs = [];
      if (text[cursor] !== '}') {
        while (true) {
          whitespace(); const key = string(); whitespace();
          requireValue(text[cursor++] === ':', 'invalid-json');
          pairs.push([key, value(depth + 1)]); whitespace();
          if (text[cursor] === '}') break;
          requireValue(text[cursor++] === ',', 'invalid-json');
        }
      }
      cursor++;
      const result = Object.create(null);
      for (const [key, item] of pairs) {
        requireValue(!own(result, key), 'duplicate-json-key');
        result[key] = item;
      }
      return result;
    }
    if (char === '[') {
      cursor++; whitespace(); const result = [];
      if (text[cursor] !== ']') {
        while (true) {
          result.push(value(depth + 1)); whitespace();
          if (text[cursor] === ']') break;
          requireValue(text[cursor++] === ',', 'invalid-json');
        }
      }
      cursor++; return result;
    }
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(token, cursor)) { cursor += token.length; return result; }
    }
    for (const token of ['NaN', 'Infinity', '-Infinity']) {
      if (text.startsWith(token, cursor)) throw new HandoffError('invalid-number');
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(cursor));
    requireValue(match !== null, 'invalid-json');
    cursor += match[0].length;
    requireValue(!/[.eE]/.test(match[0]), 'invalid-number');
    const result = Number(match[0]);
    requireValue(Number.isSafeInteger(result) && result >= 0, 'invalid-integer');
    return result;
  }
  const result = value(0); whitespace();
  requireValue(cursor === text.length, 'invalid-json');
  return result;
}

function fields(value, names) {
  requireValue(object(value) && Object.keys(value).length === names.length && names.every(name => own(value, name)), 'invalid-fields');
}
function integer(value, minimum, maximum) {
  requireValue(typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum, 'invalid-integer');
}
function identifier(value) {
  requireValue(typeof value === 'string' && value.length >= 1 && value.length <= 64 && /^[A-Za-z0-9]/.test(value)
    && !/[^A-Za-z0-9._:-]/.test(value), 'invalid-identifier');
}
function hex(value, size) { requireValue(typeof value === 'string' && value.length === size && !/[^0-9a-f]/.test(value), 'invalid-hex'); }
const time = value => integer(value, 0, TIME_MAX);
const boolean = value => requireValue(typeof value === 'boolean', 'invalid-boolean');

export function orderedJSON(value) {
  if (Array.isArray(value)) return '[' + value.map(orderedJSON).join(',') + ']';
  if (object(value)) return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + orderedJSON(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
function statusWindow(status) {
  time(status.as_of_ms); time(status.next_update_ms);
  requireValue(status.as_of_ms < status.next_update_ms, 'invalid-interval');
}
function policyShape(policy, current = false) {
  fields(policy, [...POLICY_KEYS, ...(current ? ['as_of_ms', 'next_update_ms'] : [])]);
  integer(policy.epoch, 1, 2147483647); time(policy.valid_from_ms); time(policy.valid_until_ms);
  requireValue(policy.valid_from_ms < policy.valid_until_ms, 'invalid-interval');
  fields(policy.roles, ROLES);
  for (const role of ROLES) {
    const binding = policy.roles[role];
    fields(binding, ['source_id', 'public_key', 'not_before_ms', 'not_after_ms']);
    identifier(binding.source_id); hex(binding.public_key, 64); time(binding.not_before_ms); time(binding.not_after_ms);
    requireValue(binding.not_before_ms < binding.not_after_ms, 'invalid-interval');
  }
  requireValue(policy.roles.sender.source_id !== policy.roles.receiver.source_id
    && policy.roles.sender.public_key !== policy.roles.receiver.public_key, 'ambiguous-roles');
  if (current) statusWindow(policy);
}
function arrayLimit(value, maximum) { requireValue(Array.isArray(value) && value.length <= maximum, 'input-limit'); }

function readContext(raw) {
  const context = parseStrictJSON(raw);
  fields(context, ['schema', 'expected', 'evaluation_time_ms', 'historical_policies', 'current_policy', 'key_status', 'observations']);
  requireValue(context.schema === CONTEXT_SCHEMA, 'unsupported-schema');
  const expected = context.expected;
  fields(expected, ['correlation_id', 'artifact_sha256', 'artifact_bytes', 'roles', 'window_start_ms', 'audit_cutoff_ms', 'snapshots_final_at_cutoff']);
  identifier(expected.correlation_id); hex(expected.artifact_sha256, 64); integer(expected.artifact_bytes, 1, LIMITS['artifact.bin']);
  fields(expected.roles, ROLES); ROLES.forEach(role => identifier(expected.roles[role]));
  requireValue(expected.roles.sender !== expected.roles.receiver, 'ambiguous-roles');
  time(expected.window_start_ms); time(expected.audit_cutoff_ms); time(context.evaluation_time_ms);
  requireValue(expected.window_start_ms <= expected.audit_cutoff_ms && expected.audit_cutoff_ms <= context.evaluation_time_ms, 'invalid-interval');
  boolean(expected.snapshots_final_at_cutoff);
  arrayLimit(context.historical_policies, 16); const epochs = new Set();
  for (const policy of context.historical_policies) {
    policyShape(policy);
    requireValue(!epochs.has(policy.epoch), 'ambiguous-policy'); epochs.add(policy.epoch);
  }
  if (context.current_policy !== null) {
    policyShape(context.current_policy, true);
    const currentBody = Object.fromEntries(POLICY_KEYS.map(key => [key, context.current_policy[key]]));
    const archived = context.historical_policies.find(policy => policy.epoch === currentBody.epoch);
    requireValue(!archived || orderedJSON(archived) === orderedJSON(currentBody), 'policy-epoch-conflict');
  }
  if (context.key_status !== null) {
    const status = context.key_status;
    fields(status, ['as_of_ms', 'next_update_ms', 'events']); statusWindow(status); arrayLimit(status.events, 32);
    const keys = new Set();
    for (const event of status.events) {
      fields(event, ['public_key', 'kind', 'effective_at_ms']); hex(event.public_key, 64);
      requireValue(event.kind === 'revoked' || event.kind === 'compromised', 'invalid-event'); time(event.effective_at_ms);
      requireValue(event.effective_at_ms <= status.as_of_ms, 'invalid-interval');
      requireValue(!keys.has(event.public_key), 'ambiguous-key-event'); keys.add(event.public_key);
    }
  }
  arrayLimit(context.observations, 2); const digests = new Set();
  for (const observation of context.observations) {
    fields(observation, ['receipt_sha256', 'observed_at_ms']); hex(observation.receipt_sha256, 64); time(observation.observed_at_ms);
    requireValue(observation.observed_at_ms <= context.evaluation_time_ms, 'invalid-interval');
    requireValue(!digests.has(observation.receipt_sha256), 'ambiguous-observation'); digests.add(observation.receipt_sha256);
  }
  return context;
}

function receiptShape(raw, role) {
  requireValue(raw[raw.length - 1] === 10 && raw.indexOf(10) === raw.length - 1 && raw.indexOf(13) === -1, 'invalid-receipt-line');
  const receipt = parseStrictJSON(raw, LIMITS[role + '.jsonl']);
  fields(receipt, ['step_id', 'action_id', 'params', 'success', 'ts_ms', 'seq', 'public_key', 'signature']);
  identifier(receipt.step_id); requireValue(receipt.action_id === (role === 'sender' ? 'artifact.send' : 'artifact.receive'), 'invalid-action');
  boolean(receipt.success); time(receipt.ts_ms); integer(receipt.seq, 0, 0); hex(receipt.public_key, 64); hex(receipt.signature, 128);
  const params = receipt.params;
  fields(params, ['profile', 'role', 'source_id', 'correlation_id', 'artifact_sha256', 'artifact_bytes', 'policy_epoch']);
  requireValue(params.profile === PROFILE, 'unsupported-schema'); requireValue(params.role === role, 'role-path-mismatch');
  identifier(params.source_id); identifier(params.correlation_id); hex(params.artifact_sha256, 64);
  integer(params.artifact_bytes, 1, LIMITS['artifact.bin']); integer(params.policy_epoch, 1, 2147483647);
  return receipt;
}

export function signedBytes(receipt) {
  // The selected native -01 wire contract fixes this order; params have ASCII keys.
  return Buffer.from('{"step_id":' + JSON.stringify(receipt.step_id) + ',"action_id":' + JSON.stringify(receipt.action_id)
    + ',"params":' + orderedJSON(receipt.params) + ',"success":' + JSON.stringify(receipt.success)
    + ',"ts_ms":' + String(receipt.ts_ms) + ',"seq":' + String(receipt.seq) + '}', 'utf8');
}
function signatureValid(receipt) {
  try {
    const key = createPublicKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(receipt.public_key, 'hex').toString('base64url') } });
    return verifySignature(null, signedBytes(receipt), key, Buffer.from(receipt.signature, 'hex'));
  } catch { return false; }
}
const fresh = (status, now) => status !== null && status.as_of_ms <= now && now < status.next_update_ms;
function authorizedBinding(policy, role, receipt, expected) {
  const binding = policy.roles[role];
  return binding.public_key === receipt.public_key && binding.source_id === receipt.params.source_id && binding.source_id === expected.roles[role];
}
function authorizedInterval(policy, role, at) {
  const binding = policy.roles[role];
  return policy.valid_from_ms <= at && at < policy.valid_until_ms && binding.not_before_ms <= at && at < binding.not_after_ms;
}
const eventAt = (context, key, at) => context.key_status.events.find(event => event.public_key === key && event.effective_at_ms <= at)?.kind ?? null;

function authority(context, role, receipt, verified, observed) {
  if (!verified) return ['not-evaluable-signature', 'not-evaluable-signature'];
  const now = context.evaluation_time_ms;
  const old = context.historical_policies.find(policy => policy.epoch === receipt.params.policy_epoch);
  const current = context.current_policy;
  let historical, present;
  if (!old) historical = 'insufficient-policy-archive';
  else if (!authorizedBinding(old, role, receipt, context.expected)) historical = 'not-authorized-role-binding';
  else if (observed === null) historical = 'insufficient-trusted-observation';
  else if (observed < receipt.ts_ms) historical = 'contradictory-observation-time';
  else if (!fresh(context.key_status, now)) historical = 'insufficient-fresh-key-status';
  else {
    const event = eventAt(context, receipt.public_key, observed);
    historical = event === 'compromised' ? 'indeterminate-after-compromise' : event === 'revoked' ? 'not-authorized-revoked'
      : authorizedInterval(old, role, observed) ? 'authorized-at-observation' : 'not-authorized-at-observation';
  }
  if (!fresh(current, now)) present = 'insufficient-fresh-current-policy';
  else if (!fresh(context.key_status, now)) present = 'insufficient-fresh-key-status';
  else if (eventAt(context, receipt.public_key, now) !== null) present = 'not-authorized-key-event';
  else if (current.epoch !== receipt.params.policy_epoch || !authorizedBinding(current, role, receipt, context.expected)) present = 'not-authorized-current-policy';
  else present = authorizedInterval(current, role, now) ? 'authorized-for-current-policy' : 'not-authorized-at-evaluation';
  return [historical, present];
}

function compareSnapshots(context, receipts, details) {
  const comparison = { status: 'insufficient-authenticated-projection', matched_correlations: [], missing_sides: [], conflicting_digests: false, excluded_sides: [] };
  const present = ROLES.filter(role => own(receipts, role));
  if (present.some(role => details[role].historical_authority !== 'authorized-at-observation')) return comparison;
  const expected = context.expected;
  if (present.some(role => receipts[role].params.correlation_id !== expected.correlation_id
    && atCutoff(context, receipts[role], details[role]))) {
    comparison.status = 'not-evaluable-claim-binding'; return comparison;
  }
  // Derive the selected two-source comparison directly, without an OpenPoC import.
  const included = [];
  for (const role of present) {
    if (!atCutoff(context, receipts[role], details[role])) comparison.excluded_sides.push(role);
    else included.push(role);
  }
  comparison.excluded_sides.sort();
  if (included.length === 0) { comparison.status = 'not-evaluable'; return comparison; }
  comparison.missing_sides = ROLES.filter(role => !included.includes(role)).sort();
  if (included.length === 2) {
    comparison.conflicting_digests = receipts.sender.params.artifact_sha256 !== receipts.receiver.params.artifact_sha256;
    if (!comparison.conflicting_digests) comparison.matched_correlations = [expected.correlation_id];
  }
  comparison.status = comparison.conflicting_digests || (included.length !== 2 && expected.snapshots_final_at_cutoff) ? 'violated'
    : !expected.snapshots_final_at_cutoff ? 'insufficient-snapshot-finality' : 'consistent-in-supplied-snapshots';
  return comparison;
}

function atCutoff(context, receipt, details) {
  const expected = context.expected;
  return details.observed_at_ms !== null && details.observed_at_ms <= expected.audit_cutoff_ms
    && expected.window_start_ms <= receipt.ts_ms && receipt.ts_ms <= expected.audit_cutoff_ms;
}

export function verifyHandoff(inputFiles, inputContext) {
  requireValue(object(inputFiles) && own(inputFiles, 'manifest.json') && own(inputFiles, 'artifact.bin')
    && Object.keys(inputFiles).every(name => own(LIMITS, name)), 'invalid-package-files');
  requireValue(Object.values(inputFiles).every(Buffer.isBuffer), 'invalid-bytes');
  requireValue(Buffer.isBuffer(inputContext) && inputContext.length <= 131072, 'input-limit');
  const contextBytes = Buffer.from(inputContext);
  const context = readContext(contextBytes);
  requireValue(inputFiles['manifest.json'].length <= 131072, 'input-limit');
  const manifestBytes = Buffer.from(inputFiles['manifest.json']);
  const manifest = parseStrictJSON(manifestBytes);
  fields(manifest, ['schema', 'profile', 'correlation_id', 'files']);
  requireValue(manifest.schema === PACKAGE_SCHEMA && manifest.profile === PROFILE, 'unsupported-schema');
  identifier(manifest.correlation_id);
  fields(manifest.files, Object.keys(inputFiles).filter(name => name !== 'manifest.json'));
  const files = Object.create(null);
  for (const name of Object.keys(manifest.files)) {
    const entry = manifest.files[name]; fields(entry, ['bytes', 'sha256']); integer(entry.bytes, 1, LIMITS[name]); hex(entry.sha256, 64);
    requireValue(inputFiles[name].length === entry.bytes, 'integrity-mismatch');
    files[name] = Buffer.from(inputFiles[name]);
    requireValue(sha(files[name]) === entry.sha256, 'integrity-mismatch');
  }
  const expected = context.expected;
  const artifactDigest = sha(files['artifact.bin']);
  const artifactMatch = artifactDigest === expected.artifact_sha256 && files['artifact.bin'].length === expected.artifact_bytes;
  const correlationMatch = manifest.correlation_id === expected.correlation_id;
  const observations = new Map(context.observations.map(item => [item.receipt_sha256, item.observed_at_ms]));
  const receipts = Object.create(null), details = Object.create(null), stepIds = new Set();
  for (const role of ROLES) {
    const name = role + '.jsonl';
    if (!own(files, name)) {
      details[role] = { present: false, signature: 'absent', claim_binding: 'absent', receipt_sha256: null,
        observed_at_ms: null, time_binding: 'absent', historical_authority: 'absent', current_authority: 'absent' };
      continue;
    }
    const receipt = receiptShape(files[name], role);
    requireValue(!stepIds.has(receipt.step_id), 'duplicate-step-id'); stepIds.add(receipt.step_id); receipts[role] = receipt;
    const valid = signatureValid(receipt), digest = sha(files[name]), observed = observations.get(digest) ?? null;
    const params = receipt.params;
    const claim = artifactMatch && correlationMatch && params.correlation_id === expected.correlation_id && params.source_id === expected.roles[role]
      && params.artifact_sha256 === artifactDigest && params.artifact_bytes === files['artifact.bin'].length && receipt.success;
    const [historical, current] = authority(context, role, receipt, valid, observed);
    details[role] = { present: true, signature: valid ? 'valid' : 'invalid', claim_binding: claim ? 'matches-expected-handoff' : 'mismatch',
      receipt_sha256: digest, observed_at_ms: observed,
      time_binding: observed === null ? 'missing' : observed < receipt.ts_ms ? 'contradictory' : observed > expected.audit_cutoff_ms ? 'observed-after-cutoff' : 'observed-by-cutoff',
      historical_authority: historical, current_authority: current };
  }
  const comparison = compareSnapshots(context, receipts, details);
  const mismatch = Object.keys(receipts).some(role => details[role].claim_binding === 'mismatch'
    && details[role].historical_authority === 'authorized-at-observation' && atCutoff(context, receipts[role], details[role]));
  const verdict = !artifactMatch || !correlationMatch || mismatch ? 'violated-expected-claim'
    : comparison.status === 'violated' ? 'violated-supplied-snapshot-contract'
    : comparison.status === 'consistent-in-supplied-snapshots' ? 'supported-under-receiver-context' : 'insufficient-evidence';
  return { schema: REPORT_SCHEMA, profile: PROFILE, receiver_context_sha256: sha(contextBytes), package_manifest_sha256: sha(manifestBytes),
    transport_integrity: 'matches-declared-manifest', expected_artifact_binding: artifactMatch ? 'match' : 'mismatch',
    expected_correlation_binding: correlationMatch ? 'match' : 'mismatch', evaluation_time_ms: context.evaluation_time_ms,
    audit_cutoff_ms: expected.audit_cutoff_ms, receipts: details, cross_source: comparison, handoff_at_cutoff: verdict,
    global_capture_completeness: 'unproven', trust_basis: 'receiver independently accepts policy archives, status completeness, observations and finality',
    historical_time_basis: 'authority at accepted observation, not independently proved execution/signing time',
    non_claims: ['real-world effect truth', 'production non-bypassability', 'automatic authority from bundled keys',
      'permission to execute a new action', 'external pilot or independent organizations'] };
}

function within(root, path) { const child = relative(root, path); return child === '' || (!isAbsolute(child) && child !== '..' && !child.startsWith('..\\') && !child.startsWith('../')); }
function boundedRead(path, maximum) {
  const entry = lstatSync(path);
  requireValue(entry.isFile() && !entry.isSymbolicLink(), 'invalid-filesystem-entry');
  const fd = openSync(path, 'r');
  try {
    const size = fstatSync(fd);
    requireValue(size.isFile(), 'invalid-filesystem-entry'); requireValue(size.size <= maximum, 'input-limit');
    const bytes = Buffer.alloc(maximum + 1); let offset = 0, count;
    do { count = readSync(fd, bytes, offset, bytes.length - offset, null); offset += count; } while (count && offset < bytes.length);
    requireValue(offset <= maximum, 'input-limit'); return bytes.subarray(0, offset);
  } finally { closeSync(fd); }
}
function readDirectory(packagePath, contextPath) {
  const root = realpathSync(packagePath), context = realpathSync(contextPath);
  requireValue(!within(root, context), 'self-supplied-context'); requireValue(lstatSync(root).isDirectory(), 'invalid-package-files');
  const names = [], directory = opendirSync(root);
  try {
    let entry;
    while ((entry = directory.readSync()) !== null) {
      requireValue(names.length < 4 && own(LIMITS, entry.name), 'invalid-package-files');
      names.push(entry.name);
    }
  } finally { directory.closeSync(); }
  const files = Object.create(null);
  for (const name of names) {
    const path = join(root, name);
    requireValue(!lstatSync(path).isSymbolicLink() && within(root, realpathSync(path)), 'invalid-filesystem-entry');
    files[name] = boundedRead(path, LIMITS[name]);
  }
  return { files, contextBytes: boundedRead(context, 131072), root, context };
}
export function verifyDirectory(packagePath, contextPath) {
  const input = readDirectory(packagePath, contextPath);
  return verifyHandoff(input.files, input.contextBytes);
}

export function runCorpus(rootPath) {
  const root = realpathSync(rootPath), raw = boundedRead(join(root, 'corpus.json'), 131072), corpus = parseStrictJSON(raw);
  fields(corpus, ['schema', 'keys', 'time_basis', 'cases']);
  requireValue(corpus.schema === 'ttrace.artifact-handoff-corpus/v1' && Array.isArray(corpus.cases) && corpus.cases.length > 0 && corpus.cases.length <= 1000, 'invalid-corpus');
  const cases = [], names = new Set(), inputFiles = Object.create(null);
  inputFiles['corpus.json'] = { bytes: raw.length, sha256: sha(raw) };
  for (const item of corpus.cases) {
    fields(item, ['id', 'package', 'context', 'expected', 'expected_error_code']); identifier(item.id);
    requireValue(!names.has(item.id) && object(item.expected), 'invalid-corpus'); names.add(item.id);
    requireValue(item.expected_error_code === null || typeof item.expected_error_code === 'string', 'invalid-corpus');
    requireValue(typeof item.package === 'string' && typeof item.context === 'string', 'invalid-corpus');
    const packagePath = realpathSync(resolve(root, item.package)), contextPath = realpathSync(resolve(root, item.context));
    requireValue(within(root, packagePath) && within(root, contextPath), 'invalid-corpus');
    const input = readDirectory(packagePath, contextPath);
    for (const [path, bytes] of [[input.context, input.contextBytes], ...Object.entries(input.files).map(([name, bytes]) => [join(input.root, name), bytes])]) {
      const name = relative(root, path).split('\\').join('/'), descriptor = { bytes: bytes.length, sha256: sha(bytes) };
      requireValue(!own(inputFiles, name) || orderedJSON(inputFiles[name]) === orderedJSON(descriptor), 'corpus-input-changed');
      inputFiles[name] = descriptor;
    }
    let report;
    try { report = verifyHandoff(input.files, input.contextBytes); }
    catch (error) {
      if (!(error instanceof HandoffError) || error.code !== item.expected_error_code) throw error;
      cases.push({ id: item.id, status: 'agree', error_code: error.code }); continue;
    }
    requireValue(item.expected_error_code === null, 'corpus-disagreement', item.id + ': expected error not raised');
    for (const [path, expected] of Object.entries(item.expected)) {
      let actual = report;
      for (const part of path.split('.')) { requireValue(object(actual) && own(actual, part), 'corpus-disagreement'); actual = actual[part]; }
      requireValue(orderedJSON(actual) === orderedJSON(expected), 'corpus-disagreement', item.id + ': ' + path);
    }
    requireValue(report.global_capture_completeness === 'unproven', 'corpus-disagreement');
    cases.push({ id: item.id, status: 'agree', report });
  }
  return { schema: 'ttrace.handoff-node-corpus-report/v1', corpus_sha256: sha(raw),
    corpus_inputs_sha256: sha(Buffer.from(orderedJSON(inputFiles))), input_files: inputFiles,
    case_count: cases.length, agree_count: cases.length, cases,
    non_claim: 'separate implementation; not independent organizations, a separate cryptographic backend, or an external pilot' };
}

export function main(args = process.argv.slice(2)) {
  try {
    let report;
    if (args.length === 2 && args[0] === 'corpus') report = runCorpus(args[1]);
    else {
      requireValue(args.length === 4 && args[0] === 'verify' && args[2] === '--receiver-context', 'invalid-arguments',
        'Usage: node artifact-handoff.mjs verify PACKAGE --receiver-context CONTEXT | corpus CORPUS');
      report = verifyDirectory(args[1], args[3]);
    }
    process.stdout.write(JSON.stringify(report, null, 2) + '\n'); return 0;
  } catch (error) {
    const code = error instanceof HandoffError ? error.code : 'input-unavailable';
    process.stdout.write(JSON.stringify({ schema: REPORT_SCHEMA, profile: PROFILE, status: 'invalid-input', error: { code,
      message: error instanceof HandoffError ? error.message : 'required input could not be read' } }) + '\n');
    return 2;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
