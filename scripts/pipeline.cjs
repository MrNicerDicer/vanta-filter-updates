'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { buildSnapshot, maximumBytes, sha256 } = require('./seed.cjs');
const { prepareText, makePackage, verifyPackage } = require('./vfu.cjs');

const repo = 'MrNicerDicer/vanta-filter-updates';
const repositoryFile = path.join(__dirname, '../LICENSE-EasyList.txt');
const staging = path.join(__dirname, '../.vanta-staging');
const maxPackage = maximumBytes + 256;
const ttl = 7 * 86400;
const renewBefore = 3 * 86400;

function planUpdate(mode, previous, baseline, now) {
  if (!['production', 'test-one', 'test-two'].includes(mode)) throw Error('Unsupported publication mode');
  const current = previous?.sequence ?? 0;
  if (mode === 'test-one' && current !== 0) throw Error('Test channel already initialized');
  if (mode === 'test-two' && current !== 1) throw Error('Test sequence 1 must be published first');
  const fixture = { 'test-one': 'one.js', 'test-two': 'two.js' }[mode];
  const rules = fixture
    ? Buffer.concat([baseline, Buffer.from('||vanta-update-fixture.test/' + fixture + '$script\n')])
    : baseline;
  if (mode === 'production' && previous?.rules.equals(rules) && previous.expires > now + renewBefore) return;
  return { sequence: current + 1, issued: now, expires: now + ttl, rules };
}

async function prepare(output = staging) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'vanta-filters-'));
  try {
    const snapshot = await buildSnapshot(scratch);
    const bytes = fs.readFileSync(path.join(snapshot, 'vanta-filter-seed.txt'));
    const upstream = JSON.parse(fs.readFileSync(path.join(snapshot, 'snapshot.json'), 'utf8'));
    for (const input of upstream.sources) {
      const minimum = { easylist: 30000, easyprivacy: 20000, easylistgermany: 2000 }[input.id];
      if (!minimum || input.retained < minimum) throw Error('Unexpectedly small upstream list: ' + input.id);
      const raw = fs.readFileSync(path.join(snapshot, input.id + '.source.txt'));
      if (sha256(raw) !== input.sha256) throw Error('Source provenance digest mismatch');
      const header = raw.toString('utf8').split(/\r?\n/, 32);
      input.revision = header.find(line => /^! Commit: [a-f0-9]{40}$/.test(line))?.slice(10) ?? null;
      input.notices = header.filter(line => /^!\s+(?:copyright|licen[cs]e|attribution)\b/i.test(line));
      if (input.notices.length !== 1 ||
          input.notices[0].trim() !== '! Licence: https://easylist.to/pages/licence.html') {
        throw Error('Upstream licence notice changed or is missing: ' + input.id);
      }
    }
    const { rules, exclusions } = prepareText(bytes);
    fs.mkdirSync(output);
    fs.writeFileSync(path.join(output, 'rules.txt'), rules, { flag: 'wx' });
    fs.writeFileSync(path.join(output, 'provenance.json'), JSON.stringify({
      sourceSeedSha256: upstream.sha256,
      baselineSha256: sha256(rules),
      sources: upstream.sources,
      baselineExclusions: exclusions,
      workflowCommit: /^[a-f0-9]{40}$/.test(process.env.GITHUB_SHA ?? '') ? process.env.GITHUB_SHA : null,
    }, null, 2) + '\n', { flag: 'wx' });
    console.log('Validated three upstream lists, baseline SHA-256:', sha256(rules));
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function github(token, fetcher = fetch) {
  if (!token) throw Error('GitHub workflow token missing');
  return async function api(route, { method = 'GET', data, allowMissing = false, raw = false } = {}) {
    const response = await fetcher('https://api.github.com/repos/' + repo + route, {
      method,
      redirect: 'error',
      signal: AbortSignal.timeout(60000),
      headers: {
        authorization: 'Bearer ' + token,
        'content-type': 'application/json',
        accept: raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json',
        'x-github-api-version': '2026-03-10',
        'user-agent': 'vanta-filter-publisher',
      },
      body: data === undefined ? undefined : JSON.stringify(data),
    });
    if (allowMissing && response.status === 404) return;
    if (!response.ok) throw Error('GitHub API ' + method + ' ' + route.split('?')[0] + ' returned ' + response.status);
    if (!raw) return response.json();
    const pieces = [];
    let total = 0;
    for await (const piece of response.body) {
      total += piece.length;
      if (total > maxPackage) throw Error('Published package exceeds native limit');
      pieces.push(piece);
    }
    return Buffer.concat(pieces, total);
  };
}

async function publishFiles(api, branch, head, files, sequence) {
  const tree = [];
  for (const [name, bytes] of Object.entries(files)) {
    const blob = await api('/git/blobs', { method: 'POST',
      data: { content: bytes.toString('base64'), encoding: 'base64' } });
    tree.push({ path: name, mode: '100644', type: 'blob', sha: blob.sha });
  }
  const gitTree = await api('/git/trees', { method: 'POST', data: { tree } });
  const commit = await api('/git/commits', { method: 'POST', data: {
    message: 'Publish VANTA filter sequence ' + sequence,
    author: { name: 'github-actions[bot]', email: '41898282+github-actions[bot]@users.noreply.github.com' },
    committer: { name: 'github-actions[bot]', email: '41898282+github-actions[bot]@users.noreply.github.com' },
    tree: gitTree.sha,
    parents: head ? [head] : [],
  } });
  if (head) {
    await api('/git/refs/heads/' + branch, { method: 'PATCH', data: { sha: commit.sha, force: false } });
  } else {
    await api('/git/refs', { method: 'POST', data: { ref: 'refs/heads/' + branch, sha: commit.sha } });
  }
}

async function publish() {
  if (process.env.GITHUB_REPOSITORY !== repo || process.env.GITHUB_REF !== 'refs/heads/main' ||
      !['schedule', 'workflow_dispatch'].includes(process.env.GITHUB_EVENT_NAME)) {
    throw Error('Publication is limited to the canonical main workflow');
  }
  const mode = process.env.VANTA_MODE;
  if (!['production', 'test-one', 'test-two'].includes(mode) ||
      (process.env.GITHUB_EVENT_NAME === 'schedule' && mode !== 'production')) {
    throw Error('Unexpected publication mode');
  }
  let key;
  try { key = crypto.createPrivateKey(process.env.VANTA_FILTER_SIGNING_KEY ?? ''); }
  catch { throw Error('Missing or invalid environment signing key'); }
  delete process.env.VANTA_FILTER_SIGNING_KEY;
  if (key.asymmetricKeyType !== 'ed25519') throw Error('Signing key must be Ed25519');
  const publicKey = crypto.createPublicKey(key);
  const rawPublicKey = publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('hex');
  if (rawPublicKey !== process.env.VANTA_FILTER_PUBLIC_KEY) throw Error('Signer does not match environment public key');
  const api = github(process.env.GITHUB_TOKEN);
  const branch = mode === 'production' ? 'filters' : 'filters-test';
  const ref = await api('/git/ref/heads/' + branch, { allowMissing: true });
  const head = ref?.object?.sha;
  if (ref && !/^[a-f0-9]{40}$/.test(head)) throw Error('Invalid publication branch head');
  const now = Math.floor(Date.now() / 1000);
  const previousPackage = head && await api('/contents/filters.vfu?ref=' + head, { raw: true });
  const previous = previousPackage && verifyPackage(previousPackage, publicKey, 0, now, { installed: true });
  const baseline = fs.readFileSync(path.join(staging, 'rules.txt'));
  const provenance = JSON.parse(fs.readFileSync(path.join(staging, 'provenance.json'), 'utf8'));
  if (sha256(baseline) !== provenance.baselineSha256) throw Error('Staged baseline was changed');
  const update = planUpdate(mode, previous, baseline, now);
  if (!update) {
    console.log('Unchanged and sufficiently fresh. Publication skipped.');
    return;
  }
  const { sequence, issued, expires, rules } = update;
  const pkg = makePackage(rules, key, sequence, issued, expires);
  verifyPackage(pkg, publicKey, previous?.sequence ?? 0, now);
  const manifest = Buffer.from(JSON.stringify({
    schema: 1, kind: 'vanta-standard-text', sequence,
    issuedAt: new Date(issued * 1000).toISOString(),
    expiresAt: new Date(expires * 1000).toISOString(),
    bytes: rules.length, sha256: sha256(rules),
    format: 'VANTA-FILTER-TEXT-1', packageSha256: sha256(pkg), channel: branch,
    attribution: 'The EasyList authors (https://easylist.to/)',
    license: 'CC-BY-SA-3.0; see LICENSE-EasyList.txt and upstream per-file notices',
    ...provenance,
  }, null, 2) + '\n');
  await publishFiles(api, branch, head, {
    'filters.vfu': pkg,
    'manifest.json': manifest,
    'LICENSE-EasyList.txt': fs.readFileSync(repositoryFile),
  }, sequence);
  console.log('Published', branch, 'sequence', sequence, 'VFU SHA-256', sha256(pkg));
}

if (require.main === module) {
  const action = process.argv[2];
  const operation = action === 'prepare' ? prepare : action === 'publish' ? publish : undefined;
  if (!operation) {
    console.error('Usage: pipeline.cjs prepare | publish');
    process.exitCode = 2;
  } else {
    operation().catch(error => { console.error(error.message); process.exitCode = 1; });
  }
}
module.exports = { planUpdate, publishFiles, github, prepare };
