'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const sources = [
  ['easylist', 'https://easylist.to/easylist/easylist.txt'],
  ['easyprivacy', 'https://easylist.to/easylist/easyprivacy.txt'],
  ['easylistgermany', 'https://easylist.to/easylistgermany/easylistgermany.txt'],
];
const maximumBytes = 8 * 1024 * 1024;
const maximumRuleBytes = 32 * 1024;
const maximumRegexRuleBytes = 4 * 1024;
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');

function parseList(bytes, source = 'Filterliste', stats = {}, onExcluded = () => {}) {
  if (!bytes.length || bytes.length > maximumBytes) {
    throw Error(source + ': Dateigroesse ' + bytes.length + ' Bytes ausserhalb 1-' + maximumBytes);
  }
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const fail = (line, byteLength, reason, text) => {
    const characterCount = text === undefined ? '' : ', ' + [...text].length + ' Unicode-Zeichen';
    throw Error(source + ', Zeile ' + line + ' (' + byteLength + ' UTF-8-Bytes' + characterCount + '): ' + reason);
  };
  let lines;
  try { lines = decoder.decode(bytes).split('\n'); }
  catch {
    let start = 0;
    let line = 1;
    while (start < bytes.length) {
      const newline = bytes.indexOf(0x0a, start);
      let end = newline < 0 ? bytes.length : newline;
      if (newline >= 0 && bytes[end - 1] === 0x0d) end--;
      try { decoder.decode(bytes.subarray(start, end)); }
      catch { fail(line, end - start, 'ungueltiges UTF-8'); }
      if (newline < 0) break;
      start = newline + 1;
      line++;
    }
    throw Error(source + ': ungueltiges UTF-8');
  }
  const rules = [];
  const conditionals = [];
  Object.assign(stats, { lf: 0, crlf: 0, bom: false, conditionalExcluded: 0,
    resourceExcluded: 0, proceduralExcluded: 0, aboveOldLimit: 0, maxRuleBytes: 0 });
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (i + 1 < lines.length) {
      if (line.endsWith('\r')) { stats.crlf++; line = line.slice(0, -1); }
      else stats.lf++;
    }
    if (i === 0 && line.startsWith('\ufeff')) { stats.bom = true; line = line.slice(1); }
    const length = Buffer.byteLength(line);
    const control = /[\u0000-\u001f\u007f-\u009f\ufeff]/u.exec(line);
    if (control) {
      const code = control[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
      const reason = code === '000D' ? 'CR ohne nachfolgendes LF' : code === 'FEFF'
        ? 'BOM nur am Dateianfang erlaubt' : 'unerwartetes Steuerzeichen U+' + code;
      fail(i + 1, length, reason + ' in Spalte ' + ([...line.slice(0, control.index)].length + 1), line);
    }
    if (i === 0) {
      if (!/^\[Adblock Plus(?: [\d.]+)?\]$/i.test(line)) fail(1, length, 'ABP-Header fehlt', line);
      continue;
    }
    const rule = line.trim();
    if (/^!#if(?:\s|$)/i.test(rule)) { conditionals.push(i); continue; }
    if (/^!#endif(?:\s|$)/i.test(rule)) {
      if (!conditionals.length) fail(i + 1, length, 'ENDIF ohne IF', line);
      conditionals.pop();
      continue;
    }
    if (!rule || rule.startsWith('!')) continue;
    if (conditionals.length) { stats.conditionalExcluded++; continue; }
    if (rule.startsWith('<') || rule.startsWith('[')) fail(i + 1, length, 'unerwarteter Dokumentinhalt', line);
    const limit = /^(?:@@)?\/.+\/(?:\$.*)?$/.test(rule) ? maximumRegexRuleBytes : maximumRuleBytes;
    if (length > limit) fail(i + 1, length, 'Regel ueberschreitet das Limit von ' + limit + ' UTF-8-Bytes', line);
    if (length > 4096) stats.aboveOldLimit++;
    stats.maxRuleBytes = Math.max(stats.maxRuleBytes, length);
    // Keep ordinary network rules and CSS. No executable or rewriting resources.
    if ((/#(?:@)?[$%?#]/.test(rule) && !/#(?:@)?##?/.test(rule)) ||
        /\+js\s*\(|(?:^|[, $])(?:redirect(?:-rule)?|rewrite|replace|csp|permissions|header|removeheader|urltransform|uritransform)(?:[=,$]|$)/i.test(rule)) {
      stats.resourceExcluded++;
      onExcluded('resource', i + 1, rule);
      continue;
    }
    if (/#(?:@)?#/.test(rule) && /:(?:style|remove|xpath|matches-[a-z]+|upward|watch-attr|if|if-not)\s*\(/i.test(rule)) {
      stats.proceduralExcluded++;
      onExcluded('procedural', i + 1, rule);
      continue;
    }
    rules.push(rule);
  }
  if (conditionals.length) {
    const i = conditionals.at(-1);
    fail(i + 1, Buffer.byteLength(lines[i]), 'IF ohne ENDIF', lines[i]);
  }
  return rules;
}

async function download(url) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(30000) });
  if (!response.ok || !response.body) throw Error('HTTP ' + response.status + ' from ' + url);
  if (/html/i.test(response.headers.get('content-type') || '')) throw Error('Unexpected HTML from ' + url);
  const chunks = [];
  let count = 0;
  for await (const chunk of response.body) {
    count += chunk.length;
    if (count > maximumBytes) throw Error('Oversize body from ' + url);
    chunks.push(chunk);
  }
  return { bytes: Buffer.concat(chunks), modified: response.headers.get('last-modified') };
}

async function buildSnapshot(parent) {
  const rules = new Set();
  const inputs = [];
  const raw = [];
  for (const [id, url] of sources) {
    const source = id + ' (' + url + ')';
    let input;
    try { input = await download(url); }
    catch (error) { throw Error(source + ': Abruf fehlgeschlagen: ' + (error.cause?.code || error.message)); }
    const { bytes, modified } = input;
    const digest = sha256(bytes);
    const stats = {};
    let parsed;
    try {
      parsed = parseList(bytes, source, stats);
      if (parsed.length < 1000) throw Error(source + ': weniger als 1000 verwendbare Regeln');
    } catch (error) {
      // Keep the exact response for analysis. It is never a build input.
      fs.mkdirSync(parent, { recursive: true });
      const rejected = path.join(parent, 'rejected-' + id + '-' + digest + '.source.txt');
      try { fs.writeFileSync(rejected, bytes, { flag: 'wx' }); }
      catch (writeError) { if (writeError.code !== 'EEXIST') throw Error(error.message + '; Rohdaten konnten nicht gesichert werden: ' + writeError.message); }
      throw Error(error.message + '; SHA-256 ' + digest + '; Rohdaten: ' + rejected);
    }
    console.error(source + ': ' + JSON.stringify({ sha256: digest, lastModified: modified, ...stats }));
    for (const rule of parsed) rules.add(rule);
    inputs.push({ id, url, modified, bytes: bytes.length, sha256: digest, retained: parsed.length, validation: stats,
      license: 'GPL-3.0-or-later OR CC-BY-SA-3.0-or-later; see upstream per-file notices' });
    raw.push([id, bytes]);
  }
  const seed = Buffer.from('[Adblock Plus 2.0]\n! VANTA snapshot: EasyList, EasyPrivacy, EasyList Germany\n' +
    '! Source and licence: https://easylist.to/pages/licence.html\n' + [...rules].join('\n') + '\n');
  if (seed.length > maximumBytes) throw Error('Combined list exceeds size bound');
  const digest = sha256(seed);
  fs.mkdirSync(parent, { recursive: true });
  const output = fs.mkdtempSync(path.join(parent, 'snapshot-'));
  try {
    for (const [id, bytes] of raw) fs.writeFileSync(path.join(output, id + '.source.txt'), bytes);
    fs.writeFileSync(path.join(output, 'vanta-filter-seed.txt'), seed);
    fs.writeFileSync(path.join(output, 'vanta_filter_seed_digest.h'),
      '#include <array>\n#include <cstdint>\n\n' +
      'inline constexpr std::array<uint8_t, 32> kVantaSeedSha256 = {' +
      digest.match(/../g).map(x => '0x' + x).join(', ') + '};\n');
    fs.writeFileSync(path.join(output, 'snapshot.json'), JSON.stringify({
      schema: 1, createdAt: new Date().toISOString(), sha256: digest, bytes: seed.length,
      uniqueRules: rules.size, licenseUrl: 'https://easylist.to/pages/licence.html', sources: inputs,
    }, null, 2) + '\n');
  } catch (error) {
    fs.rmSync(output, { recursive: true, force: true });
    throw error;
  }
  return output;
}

module.exports = { buildSnapshot, parseList, maximumBytes, maximumRuleBytes, maximumRegexRuleBytes, sha256 };
if (require.main === module) {
  if (process.argv.length === 5 && process.argv[2] === '--check-list') {
    const [, id, file] = process.argv.slice(2);
    try {
      if (fs.statSync(file).size > maximumBytes) throw Error(id + ': Datei ueberschreitet ' + maximumBytes + ' Bytes');
      const data = fs.readFileSync(file);
      const stats = {};
      const rules = parseList(data, id, stats);
      console.log(JSON.stringify({ source: id, sha256: sha256(data), retained: rules.length, ...stats }));
    } catch (error) { console.error(error.message); process.exitCode = 1; }
  } else if (process.argv.length !== 3) {
    console.error('Usage: node seed.cjs <snapshot-directory> | --check-list <source> <file>');
    process.exitCode = 2;
  } else {
    buildSnapshot(path.resolve(process.argv[2])).then(console.log, error => {
      console.error(error.message);
      process.exitCode = 1;
    });
  }
}
