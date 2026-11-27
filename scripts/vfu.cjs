'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { parseList, sha256, maximumBytes } = require('./seed.cjs');

const magic = 'VANTA-FILTER-TEXT-1';
const maxEpoch = 4102444800;
const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');

const unsupportedOptions = new Set(['redirect', 'redirect-rule', 'rewrite', 'replace', 'csp',
  'permissions', 'header', 'removeheader', 'urltransform', 'uritransform']);

function isBaselineRule(line) {
  if (/^[[<]|#(?:@)?(?:\?#|%|\$)/.test(line)) return false;
  const lower = line.toLowerCase();
  if (line.includes('##') || line.includes('#@#')) {
    return !/\+js|#(?:@)?#\^|[{}]|:(?:style\(|remove\(|xpath\(|matches-|upward\(|watch-attr\(|if\(|if-not\(|has-text\(|-abp-)/.test(lower);
  }
  const pattern = line.startsWith('@@') ? line.slice(2) : line;
  return !(pattern.startsWith('/') && Buffer.byteLength(pattern) > 4096) &&
    !lower.split(/[$,=~]/).some(option => unsupportedOptions.has(option));
}

function prepareText(bytes) {
  const exclusions = [];
  const retained = parseList(bytes, 'Update-Quelle', {},
    (kind, line) => exclusions.push({ line, reason: kind }));
  const baseline = retained.filter(isBaselineRule);
  const source = bytes.toString('utf8').split('\n');
  const excludedExtensions = new Set(retained.filter(rule => !isBaselineRule(rule)));
  for (const [index, rule] of source.entries()) {
    if (excludedExtensions.has(rule.trim())) exclusions.push({ line: index + 1, reason: 'baseline-profile' });
  }
  const rules = Buffer.from('[Adblock Plus 2.0]\n! Source and licence: https://easylist.to/pages/licence.html\n' +
    [...new Set(baseline)].join('\n') + '\n');
  validateText(rules);
  return { rules, exclusions };
}

function validateText(rules) {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(rules);
  if (rules.length > maximumBytes || !text.startsWith('[Adblock Plus 2.0]\n') ||
      !text.endsWith('\n') || /[\r\t]/.test(text)) throw Error('Expected canonical baseline text');
  const lines = text.split('\n').slice(1);
  if (lines.some(line => line.trim() !== line || line.startsWith('!#'))) throw Error('Non-canonical rule');
  const input = lines.filter(line => line && !line.startsWith('!'));
  const parsed = parseList(rules);
  if (input.length < 1000 || parsed.length !== input.length || new Set(input).size !== input.length ||
      input.some(line => !isBaselineRule(line))) {
    throw Error('Unsupported, duplicate or insufficient rules');
  }
}

function checkTimes(sequence, issued, expires) {
  if (!Number.isSafeInteger(sequence) || sequence < 1 ||
      !Number.isInteger(issued) || !Number.isInteger(expires) ||
      issued < 1 || expires > maxEpoch || expires <= issued || expires - issued > 604800) {
    throw Error('Invalid sequence or timestamps');
  }
}

function makePackage(rules, key, sequence, issued, expires) {
  validateText(rules);
  checkTimes(sequence, issued, expires);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw Error('Expected private Ed25519 key');
  const header = Buffer.from([magic, sequence, issued, expires, sha256(rules), ''].join('\n'), 'ascii');
  const bytes = Buffer.concat([header, rules]);
  return Buffer.concat([bytes, crypto.sign(null, bytes, key)]);
}

function verifyPackage(pkg, key, sequenceFloor, now, { installed = false } = {}) {
  if (pkg.length <= 64 || pkg.length > maximumBytes + 256 || key.asymmetricKeyType !== 'ed25519' ||
      !Number.isSafeInteger(sequenceFloor) || sequenceFloor < 0 || !Number.isFinite(now)) throw Error('Invalid package bounds');
  const bytes = pkg.subarray(0, -64);
  if (!crypto.verify(null, bytes, key, pkg.subarray(-64))) throw Error('Invalid signature');
  const fields = [];
  let offset = 0;
  for (let i = 0; i < 5; i++) {
    const end = bytes.indexOf(10, offset);
    if (end < 0 || end - offset > 64) throw Error('Malformed header');
    fields.push(bytes.subarray(offset, end).toString('latin1'));
    offset = end + 1;
  }
  const [tag, ...header] = fields;
  const [sequence, issued, expires] = header.slice(0, 3).map(Number);
  checkTimes(sequence, issued, expires);
  if (tag !== magic || [sequence, issued, expires].some((val, index) => String(val) !== header[index]) ||
      sequence <= sequenceFloor || (!installed && (issued > now + 300 || expires <= now))) throw Error('Rejected sequence or freshness');
  const rules = bytes.subarray(offset);
  if (header[3] !== sha256(rules)) throw Error('Wrong digest');
  validateText(rules);
  return { sequence, issued, expires, rules };
}

function configHeader(config) {
  const { url, ed25519PublicKey } = config;
  const endpoint = new URL(url);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password ||
      endpoint.search || endpoint.hash || !/^[a-f0-9]{64}$/.test(ed25519PublicKey) ||
      /^0+$/.test(ed25519PublicKey) || /["\\\x00-\x20]/.test(endpoint.href)) {
    throw Error('Expected fixed HTTPS URL and nonzero 32-byte Ed25519 public key in lowercase hex');
  }
  return '#include <array>\n#include <cstdint>\n\n' +
    'inline constexpr char kVantaFilterUpdateUrl[] = ' + JSON.stringify(endpoint.href) + ';\n' +
    'inline constexpr std::array<uint8_t, 32> kVantaFilterUpdateKey = {' +
    ed25519PublicKey.match(/../g).map(byte => '0x' + byte).join(', ') + '};\n';
}

if (require.main === module) {
  try {
    const [action, ...args] = process.argv.slice(2);
    if (action === 'config-header' && args.length === 1) {
      process.stdout.write(configHeader(JSON.parse(fs.readFileSync(args[0], 'utf8').replace(/^\uFEFF/, ''))));
    } else if (action === 'prepare' && args.length === 2) {
      const [sourceFile, outputFile] = args;
      if (fs.statSync(sourceFile).size > maximumBytes) throw Error('Oversize rules');
      const { rules, exclusions } = prepareText(fs.readFileSync(sourceFile));
      fs.writeFileSync(outputFile, rules, { flag: 'wx' });
      console.log(JSON.stringify({ sha256: sha256(rules), exclusions }));
    } else if (action === 'sign' && args.length === 4) {
      const [rulesFile, privateKeyFile, sequence, outputFile] = args;
      if (fs.statSync(rulesFile).size > maximumBytes) throw Error('Oversize rules');
      const rules = fs.readFileSync(rulesFile);
      const key = crypto.createPrivateKey(fs.readFileSync(privateKeyFile));
      const issued = Math.floor(Date.now() / 1000);
      const pkg = makePackage(rules, key, Number(sequence), issued, issued + 7 * 86400);
      fs.writeFileSync(outputFile, pkg, { flag: 'wx' });
      console.log(JSON.stringify({ sequence: Number(sequence), packageSha256: sha256(pkg) }));
    } else if (action === 'fixtures' && args.length === 3) {
      const [baselineFile, privateKeyFile, outputDirectory] = args;
      if (fs.statSync(baselineFile).size > maximumBytes) throw Error('Oversize rules');
      const baseline = fs.readFileSync(baselineFile);
      const key = crypto.createPrivateKey(fs.readFileSync(privateKeyFile));
      const issued = Math.floor(Date.now() / 1000);
      fs.mkdirSync(outputDirectory);
      for (const [sequence, filename] of [[1, 'one.js'], [2, 'two.js']]) {
        const rules = Buffer.concat([baseline, Buffer.from('||vanta-update-fixture.test/' + filename + '$script\n')]);
        const pkg = makePackage(rules, key, sequence, issued, issued + 86400);
        fs.writeFileSync(path.join(outputDirectory, 'sequence-' + sequence + '.vfu'), pkg, { flag: 'wx' });
        if (sequence === 2) {
          pkg[pkg.length - 1] ^= 1;
          fs.writeFileSync(path.join(outputDirectory, 'invalid-signature.vfu'), pkg, { flag: 'wx' });
        }
      }
    } else if (action === 'public-key' && args.length === 1) {
      const der = crypto.createPublicKey(fs.readFileSync(args[0])).export({ format: 'der', type: 'spki' });
      if (der.length !== 44 || !der.subarray(0, 12).equals(spkiPrefix)) throw Error('Expected Ed25519 public key');
      console.log(der.subarray(12).toString('hex'));
    } else {
      throw Error('Usage: vfu.cjs config-header config.json | prepare seed.txt rules.txt | sign rules.txt private.pem sequence next.vfu | public-key public.pem | fixtures rules.txt private.pem new-output-dir');
    }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { makePackage, verifyPackage, configHeader, prepareText };
