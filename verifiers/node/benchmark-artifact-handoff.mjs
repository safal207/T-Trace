// Benchmark worker, not part of the standalone verifier or a signing service.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { verifyHandoff, verifyDirectory, orderedJSON } from './artifact-handoff.mjs';

function hash(raw) { return createHash('sha256').update(raw).digest('hex'); }
function count(text) {
  if (!/^[1-9][0-9]*$/.test(text)) throw new Error('invalid measurement count');
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > 2000) throw new Error('measurement count outside bounds');
  return value;
}
const [packagePath, contextPath, warmupsText, samplesText] = process.argv.slice(2);
if (process.argv.length !== 6) throw new Error('expected PACKAGE CONTEXT WARMUPS SAMPLES');
const warmups = count(warmupsText), samples = count(samplesText);
if (warmups > 100) throw new Error('warmup count outside bounds');
const baseline = verifyDirectory(packagePath, contextPath);
const files = Object.fromEntries(readdirSync(packagePath).map(name => [name, readFileSync(join(packagePath, name))]));
const context = readFileSync(contextPath);
if (baseline.handoff_at_cutoff !== 'supported-under-receiver-context' || baseline.global_capture_completeness !== 'unproven'
  || baseline.cross_source.status !== 'consistent-in-supplied-snapshots') throw new Error('unexpected benchmark decision');
for (const role of ['sender', 'receiver']) {
  const item = baseline.receipts[role];
  if (item.signature !== 'valid' || item.claim_binding !== 'matches-expected-handoff'
    || item.historical_authority !== 'authorized-at-observation' || item.current_authority !== 'authorized-for-current-policy') {
    throw new Error('benchmark input is not a complete accepted-context verification');
  }
}
const reference = orderedJSON(baseline), durations = [];
for (let index = 0; index < warmups + samples; index++) {
  const start = process.hrtime.bigint();
  const report = verifyHandoff(files, context);
  const elapsed = Number(process.hrtime.bigint() - start);
  if (orderedJSON(report) !== reference) throw new Error('API result changed during timing');
  if (index >= warmups) durations.push(elapsed);
}
if (durations.some(value => !Number.isSafeInteger(value) || value <= 0)) throw new Error('invalid timer samples');
const ordered = [...durations].sort((a, b) => a - b), middle = Math.floor(samples / 2);
const inventory = Object.fromEntries(Object.entries(files).map(([name, raw]) => [name, { bytes: raw.length, sha256: hash(raw) }]));
inventory['receiver-context.json'] = { bytes: context.length, sha256: hash(context) };
const peakBytes = process.resourceUsage().maxRSS * 1024;
if (!Number.isSafeInteger(peakBytes) || peakBytes <= 0) throw new Error('process peak memory unavailable');
process.stdout.write(JSON.stringify({ schema: 'ttrace.handoff-benchmark-worker/v1', implementation: 'node',
  runtime_version: process.version, reference_checks: 1, warmups, sample_count: samples, input_sha256: hash(Buffer.from(orderedJSON(inventory))),
  full_report_sha256: hash(Buffer.from(reference)), samples_ns: durations,
  summary_ns: { count: samples, min: ordered[0], median: samples % 2 ? ordered[middle] : (ordered[middle - 1] + ordered[middle]) / 2,
    p95: ordered[Math.ceil(0.95 * samples) - 1], max: ordered[samples - 1] },
  peak_memory: { bytes: peakBytes, method: 'Node process.resourceUsage().maxRSS (KiB multiplied by 1024)' },
  memory_scope: 'whole fresh API worker including runtime, imports, input, checks and all calls',
  openssl_version: process.versions.openssl }) + '\n');
