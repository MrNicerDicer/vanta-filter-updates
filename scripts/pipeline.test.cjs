'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { planUpdate, publishFiles, github, prepare, readPredecessor, validateSigned } = require('./pipeline.cjs');
const { makePackage, verifyPackage, configHeader } = require('./vfu.cjs');
const { sha256 } = require('./seed.cjs');

const now = 1795737600;
const sample = (prefix, count) => Array.from({ length: count }, (_, id) => '||' + prefix + id + '.example.test^').join('\n');
const rules = Buffer.from('[Adblock Plus 2.0]\n' + sample('baseline', 1100) + '\n');

test('stable payload renews before expiry and never reuses a sequence', () => {
  const previous = { sequence: 16, rules, expires: now + 3 * 86400 + 1 };
  assert.equal(planUpdate('production', previous, rules, now), undefined);
  const renewal = planUpdate('production', previous, rules, now + 1);
  assert.equal(renewal.sequence, 17);
  assert.equal(renewal.expires - renewal.issued, 604800);
  assert.equal(planUpdate('production', previous, Buffer.concat([rules, rules]), now).sequence, 17);
});

test('test sequence 1 then 2 passes the existing Ed25519 format', () => {
  const key = crypto.generateKeyPairSync('ed25519');
  const first = planUpdate('test-one', undefined, rules, now);
  const p1 = makePackage(first.rules, key.privateKey, first.sequence, first.issued, first.expires);
  const check1 = verifyPackage(p1, key.publicKey, 0, now);
  assert.throws(() => planUpdate('test-two', undefined, rules, now), /first/);
  const second = planUpdate('test-two', check1, rules, now + 1);
  const p2 = makePackage(second.rules, key.privateKey, second.sequence, second.issued, second.expires);
  const check2 = verifyPackage(p2, key.publicKey, check1.sequence, now + 1);
  assert.equal(check2.sequence, 2);
  assert.match(check1.rules.toString(), /fixture\.test\/one\.js/);
  assert.match(check2.rules.toString(), /fixture\.test\/two\.js/);
  assert.doesNotMatch(check2.rules.toString(), /fixture\.test\/one\.js/);
  assert.throws(() => verifyPackage(p1, key.publicKey, check2.sequence, now + 1), /sequence/);
  p2[p2.length - 1] ^= 1;
  assert.throws(() => verifyPackage(p2, key.publicKey, check1.sequence, now + 1), /signature/);
  const hex = key.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
  assert.match(configHeader({
    url: 'https://raw.githubusercontent.com/MrNicerDicer/vanta-filter-updates/filters-test/filters.vfu',
    ed25519PublicKey: hex,
  }), /raw\.githubusercontent\.com/);
});

test('publication changes the ref only after blobs and tree and never force pushes', async () => {
  const routes = [];
  const api = async (route, options) => {
    routes.push({ route, ...options });
    return { sha: 'a'.repeat(40) };
  };
  await publishFiles(api, 'filters', 'b'.repeat(40), {
    'filters.vfu': Buffer.from('vfu'), 'manifest.json': Buffer.from('{}'),
  }, 17);
  assert.deepEqual(routes.map(x => x.route),
    ['/git/blobs', '/git/blobs', '/git/trees', '/git/commits', '/git/refs/heads/filters']);
  assert.deepEqual(routes[3].data.parents, ['b'.repeat(40)]);
  assert.equal(routes.at(-1).data.force, false);

  const failing = [];
  await assert.rejects(() => publishFiles(async route => {
    failing.push(route);
    if (route === '/git/trees') throw Error('API error');
    return { sha: 'a'.repeat(40) };
  }, 'filters-test', undefined, { 'filters.vfu': Buffer.from('vfu') }, 1), /API error/);
  assert.deepEqual(failing, ['/git/blobs', '/git/trees']);
});

test('API uses only canonical HTTPS, forbids redirects and bounds the existing package', async () => {
  const api = github('synthetic-test-token', async (url, options) => {
    assert.match(url, /^https:\/\/api\.github\.com\/repos\/MrNicerDicer\/vanta-filter-updates\//);
    assert.equal(options.redirect, 'error');
    return new Response(Buffer.alloc(8 * 1024 * 1024 + 257));
  });
  await assert.rejects(() => api('/contents/filters.vfu', { raw: true }), /exceeds byte limit/);
});

test('fetches only fixed sources, records provenance and rejects an invalid source', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vanta-pipeline-test-'));
  const oldFetch = globalThis.fetch;
  const counts = { easylist: 30000, easyprivacy: 20000, easylistgermany: 2000 };
  let invalid = false;
  try {
    globalThis.fetch = async (url, options) => {
      assert.match(url, /^https:\/\/easylist\.to\//);
      assert.equal(options.redirect, 'error');
      const id = path.basename(url, '.txt');
      assert.ok(Object.hasOwn(counts, id));
      return new Response(invalid && id === 'easyprivacy' ? '<html>error</html>' :
        '[Adblock Plus 2.0]\n! Commit: ' + 'a'.repeat(40) + '\n' +
        '! Licence: https://easylist.to/pages/licence.html\n' + sample(id, counts[id]) + '\nexample.test##+js(set, a, b)\n');
    };
    const target = path.join(directory, 'valid');
    await prepare(target);
    const info = JSON.parse(fs.readFileSync(path.join(target, 'provenance.json'), 'utf8'));
    assert.equal(info.baselineSha256, sha256(fs.readFileSync(path.join(target, 'rules.txt'))));
    assert.equal(info.sources.length, 3);
    assert.ok(info.sources.every(source => source.revision === 'a'.repeat(40) && source.validation.resourceExcluded === 1));
    assert.doesNotMatch(fs.readFileSync(path.join(target, 'rules.txt'), 'utf8'), /\+js/);
    invalid = true;
    await assert.rejects(() => prepare(path.join(directory, 'invalid')), /easyprivacy/);
    assert.equal(fs.existsSync(path.join(directory, 'invalid')), false);
  } finally {
    globalThis.fetch = oldFetch;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('reads commit-pinned predecessor via Base64 Git Blob and verifies manifest digest', async () => {
  const key = crypto.generateKeyPairSync('ed25519');
  const pkg = makePackage(rules, key.privateKey, 1, now, now + 3600);
  const head = 'b'.repeat(40);
  const sha = crypto.createHash('sha1').update('blob ' + pkg.length + '\0').update(pkg).digest('hex');
  const encoded = pkg.toString('base64').match(/.{1,60}/g).join('\n');
  const metadata = { type: 'file', path: 'filters.vfu', size: pkg.length, sha, content: '', encoding: 'none' };
  const manifest = { schema: 1, kind: 'vanta-standard-text', channel: 'filters-test', packageSha256: sha256(pkg) };
  const calls = [];
  let blob = { sha, size: pkg.length, encoding: 'base64', content: encoded };
  const api = async (route, options) => {
    calls.push(route);
    if (route === '/contents/filters.vfu?ref=' + head) {
      assert.equal(options.accept, 'application/vnd.github.object+json');
      return metadata;
    }
    if (route === '/git/blobs/' + sha) return blob;
    if (route === '/contents/manifest.json?ref=' + head) return Buffer.from(JSON.stringify(manifest));
    assert.fail(route);
  };
  const previous = await readPredecessor(api, 'filters-test', head);
  assert.deepEqual(previous.bytes, pkg);
  assert.equal(validateSigned('Predecessor', previous.bytes, key.publicKey, 0, now).sequence, 1);
  assert.deepEqual(calls, ['/contents/filters.vfu?ref=' + head, '/git/blobs/' + sha,
    '/contents/manifest.json?ref=' + head]);
  manifest.packageSha256 = '0'.repeat(64);
  await assert.rejects(() => readPredecessor(api, 'filters-test', head), /published manifest/);
  blob = { ...blob, encoding: 'utf-8' };
  await assert.rejects(() => readPredecessor(api, 'filters-test', head), /Blob API metadata/);
  blob = { ...blob, encoding: 'base64', content: '@' + encoded.slice(1) };
  await assert.rejects(() => readPredecessor(api, 'filters-test', head), /Invalid Git Blob Base64/);
  const wrong = Buffer.from(pkg);
  wrong[wrong.length - 1] ^= 1;
  blob = { ...blob, content: wrong.toString('base64') };
  await assert.rejects(() => readPredecessor(api, 'filters-test', head), /object ID mismatch/);
});

test('distinguishes predecessor and new candidate signature failures and retains sequence floor', () => {
  const key = crypto.generateKeyPairSync('ed25519');
  const old = makePackage(rules, key.privateKey, 1, now, now + 3600);
  const next = makePackage(rules, key.privateKey, 2, now, now + 3600);
  const wrongKey = crypto.generateKeyPairSync('ed25519').publicKey;
  assert.throws(() => validateSigned('Predecessor', old, wrongKey, 0, now, { installed: true }),
    /Predecessor verification failed: Invalid signature/);
  assert.throws(() => validateSigned('New candidate', next, wrongKey, 1, now),
    /New candidate verification failed: Invalid signature/);
  assert.throws(() => validateSigned('New candidate', old, key.publicKey, 1, now),
    /New candidate verification failed: Rejected sequence/);
});
