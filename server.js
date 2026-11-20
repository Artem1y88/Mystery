const express = require('express');
const cron = require('node-cron');
const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');

// ============================================================
// 🔌 PROXY DEPENDENCY LOADING (safe — never crashes the server)
// ============================================================
let HttpsProxyAgent = null;
let SocksProxyAgent = null;
let proxyDepsAvailable = false;
try {
    ({ HttpsProxyAgent } = require('https-proxy-agent'));
    ({ SocksProxyAgent } = require('socks-proxy-agent'));
    proxyDepsAvailable = true;
    console.log('✅ Proxy dependencies loaded');
} catch (e) {
    console.error('❌ Proxy dependencies NOT installed:', e.message);
    console.error('   Fix: run `npm install https-proxy-agent socks-proxy-agent` and redeploy.');
    console.error('   Server will start WITHOUT proxy until this is fixed.');
}

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// 🌐 PROXY CONFIGURATION (STRICT — ALL API CALLS GO VIA PROXY)
// ============================================================
const PROXY_TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS) || 45000;
const PROXY_MAX_RETRIES = Number(process.env.PROXY_MAX_RETRIES) || 2;

function redactProxyUrl(raw) {
    if (!raw) return raw;
    return raw.replace(/:\/\/([^:/@]+):([^@]+)@/, '://$1:***@');
}

function normalizeProxyUrl(raw) {
    if (!raw) return null;
    try {
        const u = new URL(raw);
        if (u.username) {
            try { u.username = encodeURIComponent(decodeURIComponent(u.username)); }
            catch { u.username = encodeURIComponent(u.username); }
        }
        if (u.password) {
            try { u.password = encodeURIComponent(decodeURIComponent(u.password)); }
            catch { u.password = encodeURIComponent(u.password); }
        }
        return u.toString();
    } catch (e) {
        console.warn(`⚠️ PROXY_URL could not be parsed (${e.message}). Using raw value — if it contains unencoded '@' or ':', the proxy will fail.`);
        return raw;
    }
}

const PROXY_URL_RAW = process.env.PROXY_URL || null;
let PROXY_URL = null;
let PROXY_ENABLED = false;
let proxyAgent = null;

if (process.env.PROXY_ENABLED !== 'false' && PROXY_URL_RAW) {
    if (!proxyDepsAvailable) {
        console.warn('⚠️  PROXY_URL is set, but proxy packages are missing. Running WITHOUT proxy.');
        console.warn('   Fix: npm install https-proxy-agent socks-proxy-agent, then redeploy.');
    } else {
        try {
            PROXY_URL = normalizeProxyUrl(PROXY_URL_RAW);
            const isSocks = /^socks(4|5|5h)?:\/\//i.test(PROXY_URL);
            const agentOpts = { keepAlive: true, timeout: PROXY_TIMEOUT_MS };
            proxyAgent = isSocks
                ? new SocksProxyAgent(PROXY_URL, agentOpts)
                : new HttpsProxyAgent(PROXY_URL, agentOpts);
            PROXY_ENABLED = true;
            console.log(`🔄 ${isSocks ? 'SOCKS' : 'HTTP/HTTPS'} proxy enabled: ${redactProxyUrl(PROXY_URL)}`);
            if (PROXY_URL !== PROXY_URL_RAW) {
                console.log('   ℹ️ URL normalized from original (credentials re-encoded).');
            }
        } catch (error) {
            console.error('❌ Failed to create proxy agent:', error.message);
            console.log('⚠️ Continuing without proxy...');
            PROXY_ENABLED = false;
            proxyAgent = null;
        }
    }
} else {
    console.log('ℹ️ Proxy not configured or disabled. Using direct connections.');
}

// ============================================================
// 🌐 AXIOS — SINGLETON INSTANCE, PROXY HARD-WIRED
//     proxy:false prevents axios from also reading HTTP(S)_PROXY from env,
//     which is what causes the classic "double proxy hop" timeouts.
// ============================================================
const axiosInstance = axios.create({
    timeout: PROXY_TIMEOUT_MS,
    maxRedirects: 5,
    ...(PROXY_ENABLED && proxyAgent
        ? { httpAgent: proxyAgent, httpsAgent: proxyAgent, proxy: false }
        : {}),
});

// ============================================================
// 🔁 RETRY / ERROR CLASSIFICATION
// ============================================================
const RETRIABLE_NETWORK_CODES = new Set([
    'ECONNRESET', 'ECONNABORTED', 'ETIMEDOUT', 'EAI_AGAIN',
    'ENETUNREACH', 'EHOSTUNREACH', 'ENOTFOUND',
    'ESOCKETTIMEDOUT', 'EPIPE', 'ECONNREFUSED',
]);

function getErrorCode(err) {
    return err?.code || err?.cause?.code || null;
}
function isNetworkError(err) {
    const code = getErrorCode(err);
    if (code && RETRIABLE_NETWORK_CODES.has(code)) return true;
    const msg = (err?.message || '').toLowerCase();
    return (
        msg.includes('socket hang up') ||
        msg.includes('network error') ||
        msg.includes('timeout') ||
        msg.includes('timed out')
    );
}
function isProxyError(err) {
    if (!PROXY_ENABLED) return false;
    const code = getErrorCode(err);
    const msg = (err?.message || '').toLowerCase();
    return (
        msg.includes('proxy') ||
        code === 'ECONNREFUSED' ||
        code === 'ETIMEDOUT' ||
        code === 'ENETUNREACH' ||
        code === 'EHOSTUNREACH'
    );
}

// ============================================================
// 🎯 DEBUG LOGS (JWT + refreshToken redacted)
// ============================================================
const debugLogs = [];

function maskToken(t) {
    if (typeof t !== 'string' || t.length < 20) return t ? '***' : t;
    return `${t.slice(0, 6)}…${t.slice(-6)}`;
}
function maskHeaders(headers) {
    const out = {};
    for (const [k, v] of Object.entries(headers || {})) {
        const lk = k.toLowerCase();
        if (lk === 'x-user-jwt' || lk === 'authorization' || lk.includes('jwt') || lk.includes('token')) {
            out[k] = typeof v === 'string' ? maskToken(v) : '***';
        } else {
            out[k] = v;
        }
    }
    return out;
}
function maskBody(body) {
    if (!body || typeof body !== 'object') return body;
    const out = { ...body };
    for (const k of Object.keys(out)) {
        if (k.toLowerCase().includes('token')) out[k] = maskToken(out[k]);
    }
    return out;
}

function debugLog(userId, action, url, method, headers = {}, data = null, response = null, error = null) {
    const safeHeaders = maskHeaders(headers);
    const safeBody = data ? maskBody(data) : null;
    const e = {
        timestamp: new Date().toISOString(), userId, action,
        proxy: PROXY_ENABLED ? { enabled: true, url: redactProxyUrl(PROXY_URL) } : { enabled: false },
        request: {
            url, method,
            headers: JSON.stringify(safeHeaders, null, 2),
            body: safeBody ? JSON.stringify(safeBody, null, 2) : null,
        },
        response: response ? { status: response.status, data: JSON.stringify(response.data, null, 2) } : null,
        error: error ? {
            message: error.message,
            code: getErrorCode(error),
            status: error.response?.status,
            data: error.response?.data ? JSON.stringify(error.response.data, null, 2) : null,
        } : null,
    };
    debugLogs.unshift(e);
    if (debugLogs.length > 200) debugLogs.pop();
    console.log(`\n${'='.repeat(80)}\n🔍 [${e.timestamp}] ${userId} ${action}${PROXY_ENABLED ? ' (via proxy)' : ''}\n  ${method} ${url}`);
    if (safeBody) console.log('  BODY:', JSON.stringify(safeBody));
    if (response) console.log('  ✅', response.status);
    if (error) console.log('  ❌', error.message, error.response?.status || '', getErrorCode(error) || '');
    console.log('='.repeat(80) + '\n');
}

// ============================================================
// ⚙️ CONFIG — env vars
// ============================================================
const BASE_URL_REF       = process.env.BASE_URL_REF;
const BASE_URL_MONEY     = process.env.BASE_URL_MONEY;
const BASE_URL_SPRAY     = process.env.BASE_URL_SPRAY;
const BASE_URL_ACH       = process.env.BASE_URL_ACH;
const BASE_URL_OPENPACK  = process.env.BASE_URL_OPENPACK;
const USERS_CONFIG       = 'users.json';

function deriveApiBase() {
    if (process.env.BASE_URL_COLLECTIONS) return process.env.BASE_URL_COLLECTIONS.replace(/\/+$/, '');
    if (process.env.BASE_URL_MARKET)      return process.env.BASE_URL_MARKET.replace(/\/+$/, '');

    const tryStrip = (url, patterns) => {
        if (!url) return null;
        const noQuery = url.split('?')[0].replace(/\/+$/, '');
        for (const p of patterns) {
            const s = noQuery.replace(p, '');
            if (s !== noQuery) return s;
        }
        return null;
    };

    const fromSpray = tryStrip(BASE_URL_SPRAY, [/\/spinner\/spin$/, /\/spinner$/, /\/spin$/]);
    if (fromSpray) return fromSpray;

    const fromRef = tryStrip(BASE_URL_REF, [/\/auth\/refresh$/, /\/refresh$/, /\/auth$/]);
    if (fromRef) return fromRef;

    const fromMoney = tryStrip(BASE_URL_MONEY, [/\/user\/funds$/, /\/funds$/]);
    if (fromMoney) return fromMoney;

    return '';
}

const KOLEX_API_BASE = deriveApiBase();
const BASE_URL_COLLECTIONS = process.env.BASE_URL_COLLECTIONS || KOLEX_API_BASE;
const BASE_URL_MARKET      = process.env.BASE_URL_MARKET      || KOLEX_API_BASE;

let BASE_URL_SPINNER = process.env.BASE_URL_SPINNER;
if (!BASE_URL_SPINNER && BASE_URL_SPRAY) {
    BASE_URL_SPINNER = BASE_URL_SPRAY.split('?')[0].replace(/\/spin\/?$/, '');
}

// ============================================================
// 💼 BUNDLE CREATOR CONFIG
// ============================================================
const BUNDLE_CARDS_PER_BUNDLE = 4;
const BUNDLE_NAME             = 'CS';
const BUNDLE_LISTING_PRICE    = '0.14';
const BUNDLE_LISTING_DELAY_MS = 2500;
const BUNDLE_CREATE_DELAY_MS  = 2000;
const BUNDLE_MAX_PER_USER     = 200;
const CARD_MINT_THRESHOLD     = 500;
const BUNDLE_SCAN_PAGE_SIZE   = 50;
const BUNDLE_SCAN_MAX_PAGES   = 100;

// ============================================================
// 💼 CAT73 CONFIG
// ============================================================
const CAT73_CATEGORY_ID       = 73;
const CAT73_BUNDLE_CARDS      = 3;
const CAT73_BUNDLE_NAME       = 'KL exclusive bulk';
const CAT73_LISTING_PRICE     = '0.74';
const CAT73_POST_FLOW_WAIT_MS = 3000;

// ============================================================
// 📊 STATE
// ============================================================
let userData = {};
let activityLogs = [];
let globalSpinnerConfig = {
    spinnerId: 7063,
    packIds: [11953, 12053, 12079, 12121, 12145, 12316, 14356, 12343, 12350, 14554],
    autoFetch: true,
    lastAutoFetch: null,
};
let globalListingConfig = { delayMs: 2400 };
let templateCirculationCache = {};
let collectionCirculationProfiles = {};

const DEFAULT_EXCLUDED_COLLECTIONS = new Set([
    1,2,3,4,5,6,7,8,9,10,11,104,105,106,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,
    181,183,188,928,929,930,931,932,933,934,935,936,937,938,939,940,941,943,945,946,947,
    2740,2938,2939,2940,2941,2942,2943,2944,2945,2946,2947,2948,2950,2953,2954,2955,2957,2958,2959,
    2961,2964,2966,6650,6651,6652,6653,6654,6655,6656,6657,6658,6659,6660,6661,6662,6663,6664,6665,6666,
    18316,18514,18877,18911,18913,18914,18927,18928,18930,20131,18918,18932,
    11155,11156,11157,11225,11551,16411,16412,16413,2542,2543,1376,1378,1379,1380,1381,1383,1384,1385
]);

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

// ============================================================
// 💵 PRICE FORMULA (unchanged)
// ============================================================
function mintDesirability(M, circulation) {
    const m = Math.max(1, Math.floor(M));
    let B;
    if (m === 1) B = 1.00;
    else if (m === 2) B = 0.60;
    else if (m <= 5) B = 0.52 - 0.04 * (m - 3);
    else if (m <= 9) B = 0.38 - 0.025 * (m - 6);
    else if (m <= 19) B = 0.25 - 0.009 * (m - 10);
    else if (m <= 49) B = 0.15 * Math.exp(-0.035 * (m - 20));
    else B = 0.055 * Math.exp(-0.045 * (m - 50));
    if (circulation > 500 && m >= 11) B *= 0.50;
    return B;
}
function classifyTier(CL) {
    if (CL <= 150) return 'legendary';
    if (CL <= 500) return 'epic';
    return 'ordinary';
}
function tierFloor(tier, CL) {
    if (tier === 'legendary') return clamp(2.00 + 0.50 * (150 - CL) / 100, 2.00, 2.50);
    if (tier === 'epic') return clamp(0.25 + 0.15 * (500 - CL) / 250, 0.25, 0.40);
    return 0.10;
}
function mintOneValue(tier, R, CL) {
    if (tier === 'legendary') return 10.00 * Math.pow(150 / CL, 0.20) * Math.exp(0.25 * (R - 9.00));
    if (tier === 'epic')      return 5.50 * Math.pow(250 / CL, 0.55) * Math.exp(0.22 * (R - 9.00));
    return Math.min(5.50, 3.40 * Math.exp(0.28 * (R - 4.30)));
}
function randomStrength(tier, M, premium) {
    if (premium < 0.015) return 0;
    const m = Math.max(1, Math.floor(M));
    if (tier === 'legendary') {
        if (m === 1) return 0.51;
        if (m === 2) return 0.345;
        if (m <= 5) return 0.27;
    }
    if (m === 1) return 0.33;
    if (m === 2) return 0.27;
    if (m <= 9) return 0.225;
    if (m <= 19) return 0.195;
    if (m <= 49) return 0.15;
    return 0.10 * clamp(premium / 0.50, 0, 1);
}
function roundMarketPrice(v) {
    if (v < 1) return Math.round(v * 100) / 100;
    if (v < 5) return Math.round(v * 20) / 20;
    return Math.round(v * 10) / 10;
}
function deterministicRandom(seed) {
    let h = 0;
    for (let i = 0; i < seed.length; i++) { h = ((h << 5) - h) + seed.charCodeAt(i); h |= 0; }
    return ((h >>> 0) % 100000) / 50000 - 1;
}

async function loadCirculationCache() {
    try {
        const raw = await fs.readFile('circulation-cache.json', 'utf8');
        const p = JSON.parse(raw);
        templateCirculationCache = p.templateCache || {};
        collectionCirculationProfiles = p.collectionProfiles || {};
        console.log(`✅ Cache: ${Object.keys(templateCirculationCache).length} templates, ` +
                    `${Object.keys(collectionCirculationProfiles).length} collections`);
    } catch { console.log('ℹ️ No circulation cache yet'); }
}
async function saveCirculationCache() {
    try {
        await fs.writeFile('circulation-cache.json', JSON.stringify({
            templateCache: templateCirculationCache,
            collectionProfiles: collectionCirculationProfiles,
        }, null, 2));
    } catch (e) { console.error('Cache save failed:', e); }
}
function recordTemplateCirculation(templateId, minted) {
    if (!templateId || !minted || minted <= 0) return;
    templateCirculationCache[templateId] = minted;
}
function mergeCollectionObservation(collectionId, minted, rating) {
    if (!collectionId || !minted || minted <= 0) return;
    if (!collectionCirculationProfiles[collectionId]) collectionCirculationProfiles[collectionId] = [];
    const groups = collectionCirculationProfiles[collectionId];
    const found = groups.find(g => g.minted === minted);
    if (found) {
        found.count += 1;
        found.ratingMin = Math.min(found.ratingMin, rating);
        found.ratingMax = Math.max(found.ratingMax, rating);
    } else {
        groups.push({ minted, count: 1, ratingMin: rating, ratingMax: rating });
        groups.sort((a, b) => a.minted - b.minted);
    }
}
function resolveCirculation({ totalMinted, templateId, collectionId, mintNumber, rating }) {
    const M = Math.max(1, Math.floor(mintNumber || 1));
    const R = clamp(rating || 0, 0, 10);
    if (totalMinted != null && Number.isFinite(totalMinted) && totalMinted >= M) {
        recordTemplateCirculation(templateId, totalMinted);
        return { circulation: totalMinted, source: 'direct', confidence: 1.00 };
    }
    const cached = templateId != null ? templateCirculationCache[templateId] : undefined;
    if (cached !== undefined && cached >= M) {
        return { circulation: cached, source: 'template-cache', confidence: 0.98 };
    }
    const groups = collectionId != null ? (collectionCirculationProfiles[collectionId] || []) : [];
    const valid = groups.filter(g => g.minted >= M);
    if (valid.length === 1) {
        return { circulation: valid[0].minted, source: 'collection-single', confidence: 0.90 };
    }
    if (valid.length > 1) {
        let best = null, bestDist = Infinity;
        for (const g of valid) {
            let dist = 0;
            if (R < g.ratingMin) dist = g.ratingMin - R;
            else if (R > g.ratingMax) dist = R - g.ratingMax;
            if (dist < bestDist || (dist === bestDist && (best === null || g.minted > best.minted))) {
                best = g; bestDist = dist;
            }
        }
        const confidence = clamp(0.88 - bestDist * 0.15, 0.60, 0.88);
        return { circulation: best.minted, source: 'collection-rating-match', confidence };
    }
    let estimated;
    if (R >= 7.75 && M > 20) estimated = 100;
    else if (R >= 7.50) estimated = 250;
    else if (R >= 6.00) estimated = 250;
    else if (R >= 4.50) estimated = 2500;
    else estimated = 10000;
    if (estimated < M) {
        if (M <= 250) estimated = 250;
        else if (M <= 500) estimated = 500;
        else if (M <= 2500) estimated = 2500;
        else if (M <= 5000) estimated = 5000;
        else if (M <= 7500) estimated = 7500;
        else estimated = 10000;
    }
    return { circulation: estimated, source: 'rating-fallback', confidence: 0.45 };
}

function calculateListingPrice(card, userId, opts = {}) {
    const M = Math.max(1, Math.floor(card.mintNumber || 1));
    const R = clamp(card.rating || 0, 0, 10);
    const aggression = clamp(opts.aggression ?? 0, -1, 1);
    const circ = resolveCirculation({
        totalMinted: card.minted, templateId: card.templateId,
        collectionId: card.collectionId, mintNumber: M, rating: R,
    });
    const CL = circ.circulation;
    const tier = classifyTier(CL);
    const F = tierFloor(tier, CL);
    const V = Math.max(F, mintOneValue(tier, R, CL));
    const B = mintDesirability(M, CL);
    let basePrice = F + (V - F) * B;
    if (circ.source === 'rating-fallback') basePrice = F + (basePrice - F) * 0.82;
    else if (circ.source === 'collection-rating-match') basePrice = F + (basePrice - F) * 0.95;
    const premium = Math.max(0, basePrice - F);
    const rs = randomStrength(tier, M, premium);
    const period = opts.pricingPeriod || new Date().toISOString().slice(0, 10);
    const RM = (opts.randomValue != null) ? clamp(opts.randomValue, -1, 1)
                                          : deterministicRandom(`${card.id}:${userId}:${period}`);
    const randomMultiplier = Math.exp(rs * RM);
    const aggressionMultiplier = Math.exp(0.12 * aggression);
    let adjustedPrice = F + premium * randomMultiplier * aggressionMultiplier;
    const minRatio = tier === 'legendary' && M === 1 ? 0.70 : 0.78;
    const maxRatio = tier === 'legendary' && M === 1 ? 1.55 : 1.35;
    adjustedPrice = clamp(adjustedPrice, Math.max(F, basePrice * minRatio), basePrice * maxRatio);
    adjustedPrice = Math.min(adjustedPrice, 15.00);
    const finalPrice = Math.max(F, adjustedPrice);
    return {
        price: roundMarketPrice(finalPrice), basePrice: roundMarketPrice(basePrice),
        floor: F, mintOneValue: V, mintFactor: B, tier,
        circulationUsed: CL, circulationSource: circ.source, circulationConfidence: circ.confidence,
        randomValue: RM, randomStrength: rs, randomMultiplier,
        aggression, aggressionMultiplier,
    };
}
function getUserAggression(user) { return clamp(Number(user.aggression ?? 0), -1, 1); }

// ============================================================
// 🔎 PROXY PROBE (diagnostic)
// ============================================================
async function probeProxy(target = 'https://api.ipify.org?format=json') {
    const started = Date.now();
    try {
        const r = await axiosInstance.get(target, { timeout: 30000 });
        const elapsed = Date.now() - started;
        console.log(`✅ Proxy probe OK (${elapsed}ms) — egress IP: ${r.data?.ip || 'n/a'}`);
        return { success: true, elapsedMs: elapsed, data: r.data };
    } catch (e) {
        const elapsed = Date.now() - started;
        console.warn(`⚠️ Proxy probe FAILED (${elapsed}ms): ${getErrorCode(e) || ''} ${e.message}`);
        return {
            success: false, elapsedMs: elapsed, error: e.message,
            code: getErrorCode(e), isProxyError: isProxyError(e),
        };
    }
}

// ============================================================
// 🚀 INIT
// ============================================================
async function initializeApp() {
    try {
        console.log('🚀 INITIALIZING...');
        console.log(`🌐 Proxy Status: ${PROXY_ENABLED ? 'ENABLED' : 'DISABLED'}`);
        if (PROXY_ENABLED) console.log(`   Proxy URL: ${redactProxyUrl(PROXY_URL)}`);
        console.log('🔧 URL Resolution:');
        console.log(`   BASE_URL_REF       = ${BASE_URL_REF || '(unset)'}`);
        console.log(`   BASE_URL_SPRAY     = ${BASE_URL_SPRAY || '(unset)'}`);
        console.log(`   BASE_URL_MONEY     = ${BASE_URL_MONEY || '(unset)'}`);
        console.log(`   BASE_URL_SPINNER   = ${BASE_URL_SPINNER || '(unset)'}`);
        console.log(`   KOLEX_API_BASE     = ${KOLEX_API_BASE || '(EMPTY! ⚠️)'}`);
        console.log(`   BASE_URL_COLLECTIONS = ${BASE_URL_COLLECTIONS || '(EMPTY! ⚠️)'}`);
        console.log(`   BASE_URL_MARKET      = ${BASE_URL_MARKET || '(EMPTY! ⚠️)'}`);
        if (!BASE_URL_COLLECTIONS || !BASE_URL_MARKET) {
            console.warn('⚠️  Scanner will fail — set BASE_URL_COLLECTIONS and BASE_URL_MARKET env vars');
        }

        await loadUserConfig();
        await loadCirculationCache();

        try {
            const p = JSON.parse(await fs.readFile('spinner-config.json', 'utf8'));
            globalSpinnerConfig = {
                spinnerId: p.spinnerId || globalSpinnerConfig.spinnerId,
                packIds: Array.isArray(p.packIds) ? p.packIds : globalSpinnerConfig.packIds,
                autoFetch: p.autoFetch !== undefined ? !!p.autoFetch : true,
                lastAutoFetch: p.lastAutoFetch || null,
            };
        } catch { await saveSpinnerConfig(); }

        try {
            const p = JSON.parse(await fs.readFile('listing-config.json', 'utf8'));
            globalListingConfig.delayMs = p.delayMs || 2400;
        } catch { await fs.writeFile('listing-config.json', JSON.stringify(globalListingConfig, null, 2)); }

        // Non-blocking proxy probe (diagnostics only — never stalls init)
        if (PROXY_ENABLED) probeProxy().catch(() => {});

        for (const userId of Object.keys(userData)) await refreshToken(userId);
        startImmediateOperations();
        startScheduledTasks();
        startContinuousOperations();
        console.log('✅ Init complete');
    } catch (e) { console.error('❌ Init failed:', e); }
}

function startImmediateOperations() {
    setTimeout(() => {
        Object.keys(userData).forEach(userId => {
            const user = userData[userId];
            if (user.isActive && isWithinActiveWindow(userId)) {
                setTimeout(() => claimAchievements(userId), 10000);
                checkFunds(userId);
                if (!user.nextSpinTime) calculateNextSpinTime(userId);
            }
        });
    }, 120000);
}

async function loadUserConfig() {
    try {
        const users = JSON.parse(await fs.readFile(USERS_CONFIG, 'utf8'));
        for (const u of users) {
            userData[u.userId] = {
                ...u, jwtToken: null, lastRefresh: null, nextSpinTime: null,
                spinCount: 0, achievementsClaimed: 0, lastFunds: 0, lastCoronas: 0, lastUsd: 0,
                logs: [], isActive: false, dailyAchievementsDone: false, dailyFundsChecks: 0, packsOpened: 0,
                aggression: u.aggression != null ? Number(u.aggression) : 0,
                listerJitter: u.listerJitter ?? u['lister-jitter'] ?? 150,
                nextBundleCreatorTime: null,
                bundleCreatorsDone: 0,
                bundlesCreated: 0,
                _bundleCreatorRunning: false,
            };
        }
        console.log(`✅ Loaded ${users.length} users`);
    } catch (e) { console.error('❌ User config:', e); userData = {}; }
}

// ============================================================
// 🔌 API REQUEST HELPER — ALL CALLS GO THROUGH PROXY, RETRY VIA PROXY
// ============================================================
async function makeAPIRequest(url, method = 'GET', headers = {}, data = null, userId = 'system', options = {}) {
    const httpMethod = method.toUpperCase();
    const defaultRetries = httpMethod === 'GET' ? PROXY_MAX_RETRIES : 0;
    const maxRetries = options.maxRetries ?? defaultRetries;
    const baseDelayMs = options.baseDelayMs ?? 1000;
    const timeoutMs = options.timeoutMs;
    const retryOnHttpStatus = options.retryOnHttpStatus || [429, 502, 503, 504];

    let lastError = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            debugLog(userId, attempt === 0 ? 'REQ' : `REQ_RETRY_${attempt}`, url, httpMethod, headers, data);

            const config = {
                method: httpMethod.toLowerCase(),
                url,
                headers: { 'Content-Type': 'application/json', ...headers },
                data,
            };
            if (timeoutMs) config.timeout = timeoutMs;

            const response = await axiosInstance(config);

            debugLog(userId, 'RES', url, httpMethod, headers, data, response);
            return { success: true, data: response.data, status: response.status };
        } catch (error) {
            lastError = error;
            debugLog(userId, 'ERR', url, httpMethod, headers, data, null, error);

            const httpStatus = error.response?.status;
            const canRetry =
                attempt < maxRetries &&
                (isNetworkError(error) || (httpStatus && retryOnHttpStatus.includes(httpStatus)));

            if (canRetry) {
                const delay = Math.round(baseDelayMs * Math.pow(2, attempt) + Math.random() * 500);
                logActivity(
                    userId,
                    `🔄 ${httpMethod} ${url} failed (${getErrorCode(error) || httpStatus || 'unknown'})` +
                    `${isProxyError(error) ? ' [PROXY]' : ''}, retry ${attempt + 1}/${maxRetries} in ${delay}ms`
                );
                await sleep(delay);
                continue;
            }

            return {
                success: false,
                error: error.message,
                status: httpStatus,
                responseData: error.response?.data,
                code: getErrorCode(error),
                isProxyError: isProxyError(error),
            };
        }
    }

    return {
        success: false,
        error: lastError?.message || 'Unknown error',
        code: getErrorCode(lastError),
        isProxyError: isProxyError(lastError),
    };
}

// ============================================================
// 🎡 SPINNER
// ============================================================
async function saveSpinnerConfig() {
    try { await fs.writeFile('spinner-config.json', JSON.stringify(globalSpinnerConfig, null, 2)); }
    catch (e) { console.error('save spinner:', e); }
}
async function fetchAndUpdateSpinnerInfo(userId, force = false) {
    const user = userData[userId];
    if (!user?.jwtToken) { logActivity('system', `❌ Spinner: no JWT for ${userId}`); return false; }
    if (!force) {
        if (!globalSpinnerConfig.autoFetch) return false;
        if (globalSpinnerConfig.lastAutoFetch) {
            const elapsed = Date.now() - new Date(globalSpinnerConfig.lastAutoFetch).getTime();
            if (elapsed < 5 * 60 * 1000) return true;
        }
    }
    if (!BASE_URL_SPINNER) { logActivity('system', '❌ BASE_URL_SPINNER missing'); return false; }

    const url = `${BASE_URL_SPINNER}?categoryId=1`;
    const res = await makeAPIRequest(url, 'GET',
        { 'Content-Type': 'application/json', 'x-user-jwt': user.jwtToken }, null, userId);
    if (!res.success || !res.data?.data) {
        logActivity('system', `❌ Spinner fetch failed: ${res.error || 'no data'}${res.isProxyError ? ' (PROXY)' : ''}`);
        return false;
    }
    const data = res.data.data;
    const items = Array.isArray(data.items) ? data.items : [];
    const packPrizeIds = items
        .filter(it => Array.isArray(it.properties?.pack_templates) && it.properties.pack_templates.length > 0)
        .map(it => it.id);

    globalSpinnerConfig.spinnerId = data.id;
    globalSpinnerConfig.packIds = packPrizeIds;
    globalSpinnerConfig.lastAutoFetch = new Date().toISOString();
    await saveSpinnerConfig();
    logActivity('system', `🎡 Spinner: ID=${data.id}, packs=[${packPrizeIds.join(',')}]`);
    return true;
}

// ============================================================
// 🪙 TOKEN REFRESH
// ============================================================
async function refreshToken(userId) {
    const user = userData[userId];
    if (!user) { logActivity(userId, 'ERROR: user not found'); return false; }
    logActivity(userId, 'Starting token refresh...');
    const res = await makeAPIRequest(BASE_URL_REF, 'POST',
        { 'Content-Type': 'application/json' }, { refreshToken: user.refreshToken }, userId);
    if (res.success && res.data.data?.jwt) {
        user.jwtToken = res.data.data.jwt;
        user.lastRefresh = new Date().toISOString();
        user.isActive = true;
        if (res.data.data.refreshToken && res.data.data.refreshToken !== 'Not provided') {
            user.refreshToken = res.data.data.refreshToken;
            await updateUserConfig(userId, 'refreshToken', user.refreshToken);
        }
        logActivity(userId, '✅ Token refreshed');
        try { await fetchAndUpdateSpinnerInfo(userId, false); }
        catch (e) { logActivity(userId, `⚠️ Spinner auto-fetch: ${e.message}`); }
        scheduleNextTokenRefresh(userId);
        return true;
    }
    logActivity(userId, `❌ Refresh failed: ${res.error}${res.isProxyError ? ' (PROXY)' : ''}`);
    user.isActive = false;
    return false;
}
function scheduleNextTokenRefresh(userId) {
    const user = userData[userId];
    if (!user) return;
    const { h, m } = parseHHMM(user.dayStart);
    let base = utcTodayAt(h, m, 0, 0);
    base = addMs(base, 24 * 60 * 60 * 1000);
    const range = minutesToMs(20);
    const randMs = Math.floor(Math.random() * (2 * range + 1)) - range;
    const next = addMs(base, randMs);
    setTimeout(async () => {
        logActivity(userId, `🔄 Daily refresh (jitter ${Math.round(randMs/60000)}m)`);
        await refreshToken(userId);
    }, Math.max(next.getTime() - Date.now(), 1000));
    logActivity(userId, `⏰ Next refresh: ${next.toUTCString()}`);
}

// ============================================================
// 💰 FUNDS / ACHIEVEMENTS / PACKS / SPINS
// ============================================================
async function checkFunds(userId) {
    const user = userData[userId];
    if (!user?.jwtToken) return null;
    const res = await makeAPIRequest(BASE_URL_MONEY, 'GET', { 'x-user-jwt': user.jwtToken }, null, userId);
    if (res.success && res.data.data) {
        const { silvercoins = 0, coronas = 0, usd = '0' } = res.data.data;
        user.lastFunds = silvercoins; user.lastCoronas = coronas; user.lastUsd = usd;
        user.dailyFundsChecks = (user.dailyFundsChecks || 0) + 1;
        logActivity(userId, `💰 ${silvercoins.toLocaleString()} / ${coronas.toLocaleString()} / ${usd} USD`);
        return { silvercoins, coronas, usd };
    }
    if (res.status === 401 && await refreshToken(userId)) return checkFunds(userId);
    logActivity(userId, `❌ Funds: ${res.error}${res.isProxyError ? ' (PROXY)' : ''}`);
    return null;
}
async function claimAchievements(userId) {
    const user = userData[userId];
    if (!user?.jwtToken) return 0;
    const headers = { 'x-user-jwt': user.jwtToken };
    const r = await makeAPIRequest(`${BASE_URL_ACH}/${user.userId}/user`, 'GET', headers, null, userId);
    if (!r.success) {
        if (r.status === 401 && await refreshToken(userId)) return claimAchievements(userId);
        return 0;
    }
    const ids = [];
    ['achievements','daily','weekly','monthly'].forEach(cat => {
        (r.data.data[cat] || []).forEach(item => { if (item.progress?.claimAvailable) ids.push(item.id); });
    });
    if (!ids.length) { logActivity(userId, 'ℹ️ No achievements'); return 0; }
    let claimed = 0;
    for (const id of ids) {
        const c = await makeAPIRequest(`${BASE_URL_ACH}/${id}/claim/`, 'POST', headers, null, userId);
        if (c.success) claimed++;
        await sleep(800);
    }
    user.achievementsClaimed += claimed;
    logActivity(userId, `🎉 Claimed ${claimed}`);
    return claimed;
}
async function openPack(userId, packId) {
    const user = userData[userId];
    if (!user?.jwtToken) return false;
    const r = await makeAPIRequest(BASE_URL_OPENPACK, 'POST', { 'x-user-jwt': user.jwtToken }, { packId }, userId, { maxRetries: 0 });
    if (r.success) {
        user.packsOpened = (user.packsOpened || 0) + 1;
        logActivity(userId, `✅ Pack opened: ${packId} (total: ${user.packsOpened})`);
        return true;
    }
    if (r.status === 401 && await refreshToken(userId)) return openPack(userId, packId);
    return false;
}
async function executeSpin(userId) {
    const user = userData[userId];
    if (!user?.jwtToken) { calculateNextSpinTime(userId); return null; }
    if (!isWithinActiveWindow(userId)) return null;
    const spinnerId = globalSpinnerConfig.spinnerId;
    logActivity(userId, `🎰 Spin with spinner ${spinnerId}`);
    try {
        const headers = { 'x-user-jwt': user.jwtToken, 'Content-Type': 'application/json' };
        const r = await makeAPIRequest(BASE_URL_SPRAY, 'POST', headers, { spinnerId }, userId, { maxRetries: 0 });
        if (r.success) {
            const data = r.data.data;
            user.spinCount++;
            if (globalSpinnerConfig.packIds.includes(data.id) && data.packs?.length > 0) {
                await openPack(userId, data.packs[0].id);
            } else {
                logActivity(userId, `🎰 Prize ID=${data.id}`);
            }
        } else if (r.status === 401) await refreshToken(userId);
    } catch (e) { logActivity(userId, `❌ Spin: ${e.message}`); }
    finally { calculateNextSpinTime(userId); }
}
function calculateNextSpinTime(userId) {
    const user = userData[userId];
    if (!user) return;
    const base = user.baseInterval * 60 * 1000;
    const r1 = user.randomScale1 * 60 * 1000, r2 = user.randomScale2 * 60 * 1000;
    const total = base + Math.floor(Math.random() * (r2 - r1) + r1);
    user.nextSpinTime = new Date(Date.now() + total).toISOString();
    logActivity(userId, `⏰ Next spin in ${Math.round(total/60000)}m`);
}
function isWithinActiveWindow(userId) {
    const user = userData[userId];
    if (!user) return false;
    const now = new Date();
    if (!user._effectiveStartUTC || !user._effectiveEndUTC) {
        const { effectiveStart, effectiveEnd, randMs } = computeEffectiveWindow(user, now);
        user._effectiveStartUTC = effectiveStart;
        user._effectiveEndUTC = effectiveEnd;
        user._startJitterMin = Math.round(randMs / 60000);
    }
    return now >= user._effectiveStartUTC && now <= user._effectiveEndUTC;
}
function timeToMinutes(t) { const [h,m] = t.split(':').map(Number); return h*60+m; }
async function updateUserConfig(userId, field, value) {
    try {
        const users = JSON.parse(await fs.readFile(USERS_CONFIG, 'utf8'));
        const idx = users.findIndex(u => u.userId === userId);
        if (idx !== -1) { users[idx][field] = value; await fs.writeFile(USERS_CONFIG, JSON.stringify(users, null, 2)); }
    } catch (e) { console.error('updateUserConfig:', e); }
}
function logActivity(userId, message) {
    const ts = new Date().toISOString();
    const e = { timestamp: ts, userId, message };
    activityLogs.unshift(e); activityLogs = activityLogs.slice(0, 1000);
    if (userData[userId]) { userData[userId].logs.unshift(e); userData[userId].logs = userData[userId].logs.slice(0, 200); }
    console.log(`[${ts}] User ${userId}: ${message}`);
}

// ============================================================
// 🕒 TIME / SERIALIZATION
// ============================================================
function utcTodayAt(h, m, s = 0, ms = 0) { const d = new Date(); d.setUTCHours(h, m, s, ms); return d; }
function addMs(d, ms) { return new Date(d.getTime() + ms); }
function minutesToMs(m) { return m * 60 * 1000; }
function parseHHMM(s) { const [h, m] = s.split(':').map(Number); return { h, m }; }
function toISOStringOrNull(v) { if (!v) return null; try { const d = new Date(v); return isNaN(d) ? null : d.toISOString(); } catch { return null; } }

function safeUsersSnapshot() {
    const out = {};
    for (const [id, u] of Object.entries(userData)) {
        const { _achTimers, _dailyRolloverTimer, _bundleCreatorTimer, ...rest } = u;
        out[id] = { ...rest, _effectiveStartUTC: toISOStringOrNull(u._effectiveStartUTC), _effectiveEndUTC: toISOStringOrNull(u._effectiveEndUTC) };
    }
    return out;
}
function ensureTimerHolders(user) {
    ['_achTimers', '_dailyRolloverTimer', '_bundleCreatorTimer'].forEach(name => {
        const d = Object.getOwnPropertyDescriptor(user, name);
        if (!d || d.enumerable) {
            Object.defineProperty(user, name, {
                value: name === '_achTimers' ? [] : null,
                writable: true, configurable: true, enumerable: false,
            });
        }
    });
}
function computeEffectiveWindow(user, now = new Date()) {
    const { h: sh, m: sm } = parseHHMM(user.dayStart);
    const { h: eh, m: em } = parseHHMM(user.dayEnd);
    let baseStart = utcTodayAt(sh, sm), baseEnd = utcTodayAt(eh, em);
    if (baseEnd <= baseStart) baseEnd = addMs(baseEnd, 24*60*60*1000);
    if (now > baseEnd) { baseStart = addMs(baseStart, 24*60*60*1000); baseEnd = addMs(baseEnd, 24*60*60*1000); }
    const range = minutesToMs(20);
    const randMs = Math.floor(Math.random() * (2*range + 1)) - range;
    return { effectiveStart: addMs(baseStart, randMs), effectiveEnd: baseEnd, randMs };
}
function clearAchievementTimers(userId) {
    const user = userData[userId];
    if (!user) return;
    ensureTimerHolders(user);
    if (Array.isArray(user._achTimers)) user._achTimers.forEach(t => clearTimeout(t));
    Object.defineProperty(user, '_achTimers', { value: [], writable: true, configurable: true, enumerable: false });
    if (user._dailyRolloverTimer) clearTimeout(user._dailyRolloverTimer);
    Object.defineProperty(user, '_dailyRolloverTimer', { value: null, writable: true, configurable: true, enumerable: false });
    if (user._bundleCreatorTimer) clearTimeout(user._bundleCreatorTimer);
    Object.defineProperty(user, '_bundleCreatorTimer', { value: null, writable: true, configurable: true, enumerable: false });
}

// ============================================================
// 📅 DAILY PLAN
// ============================================================
function scheduleDailyPlan(userId) {
    const user = userData[userId];
    if (!user) return;
    ensureTimerHolders(user);
    clearAchievementTimers(userId);
    const now = new Date();
    const { effectiveStart, effectiveEnd, randMs } = computeEffectiveWindow(user, now);
    user._effectiveStartUTC = effectiveStart;
    user._effectiveEndUTC = effectiveEnd;
    user._startJitterMin = Math.round(randMs / 60000);
    logActivity(userId, `📅 Plan: start=${effectiveStart.toUTCString()} (jitter ${user._startJitterMin}m), end=${effectiveEnd.toUTCString()}`);

    const c1 = addMs(effectiveStart, minutesToMs(35));
    const c2 = addMs(c1, minutesToMs(8 * 60));
    const c3 = addMs(effectiveEnd, -minutesToMs(25));
    const scheduleClaim = (when, label) => {
        const delay = when.getTime() - Date.now();
        if (delay <= 0) { logActivity(userId, `⏭ ${label} skipped`); return; }
        const t = setTimeout(async () => {
            try {
                if (user.isActive) { logActivity(userId, `🏁 ${label}`); await claimAchievements(userId); }
            } catch (e) { logActivity(userId, `⚠️ ${label}: ${e.message}`); }
        }, delay);
        user._achTimers.push(t);
        logActivity(userId, `⏰ ${label} at ${when.toUTCString()}`);
    };
    scheduleClaim(c1, 'Ach #1');
    scheduleClaim(c2, 'Ach #2');
    scheduleClaim(c3, 'Ach #3');

    const listerJitterMin = Number(user.listerJitter) || 150;
    const creatorAt = addMs(effectiveStart, minutesToMs(listerJitterMin));
    const creatorDelay = creatorAt.getTime() - Date.now();
    if (creatorDelay > 0) {
        user._bundleCreatorTimer = setTimeout(async () => {
            logActivity(userId, '💼 Daily bundle creator firing (cat73 → cat1)');
            if (user.isActive && user.jwtToken) {
                try { await executeBundleCreator(userId); }
                catch (e) { logActivity(userId, `❌ Bundle creator: ${e.message}`); }
            }
        }, creatorDelay);
        user.nextBundleCreatorTime = creatorAt.toISOString();
        logActivity(userId, `⏰ Bundle creator at ${creatorAt.toUTCString()} (+${listerJitterMin}m)`);
    } else {
        user.nextBundleCreatorTime = null;
        logActivity(userId, `⏭ Bundle creator skipped (past)`);
    }

    const rolloverAt = addMs(effectiveEnd, minutesToMs(2));
    user._dailyRolloverTimer = setTimeout(() => {
        logActivity(userId, '🔁 Rollover');
        scheduleDailyPlan(userId);
    }, Math.max(rolloverAt.getTime() - Date.now(), 1000));
}
function scheduleDailyPlanForAllUsers() {
    logActivity('system', '🗓️ Scheduling all daily plans');
    Object.keys(userData).forEach(scheduleDailyPlan);
}

// ============================================================
// 📋 SCAN + LIST
// ============================================================
async function fetchMarketTemplatesForCollection(userId, headers, collectionId) {
    const out = {};
    if (!BASE_URL_MARKET) return out;
    let page = 1;
    while (page <= 20) {
        const url = `${BASE_URL_MARKET}/market/templates?type=card&page=${page}&categoryId=1&collectionIds=${collectionId}`;
        const r = await makeAPIRequest(url, 'GET', headers, null, userId);
        if (!r.success || !r.data?.data) break;
        const tpl = r.data.data.templates || [];
        for (const t of tpl) {
            const cardT = t.cardTemplate;
            if (!cardT?.id) continue;
            out[cardT.id] = {
                minted: Number(cardT.minted) > 0 ? Number(cardT.minted) : null,
                inCirculation: Number(cardT.inCirculation) > 0 ? Number(cardT.inCirculation) : null,
            };
        }
        if (tpl.length < 40) break;
        page++;
        await sleep(400);
    }
    return out;
}

async function scanUserCards(userId, opts = {}) {
    const user = userData[userId];
    if (!user?.jwtToken) return [];
    if (!BASE_URL_COLLECTIONS) {
        logActivity(userId, '❌ Scan: BASE_URL_COLLECTIONS empty — set env var (see startup log)');
        return [];
    }

    const categoryId = opts.categoryId ?? 1;
    const seasons = (opts.seasons === undefined) ? '2026' : opts.seasons;
    const skipMarketTemplates = !!opts.skipMarketTemplates;

    const headers = { 'Content-Type': 'application/json', 'x-user-jwt': user.jwtToken };
    const collected = [];

    let summaryUrl = `${BASE_URL_COLLECTIONS}/collections/users/${user.userId}/user-summary?categoryId=${categoryId}`;
    if (seasons != null && seasons !== '') {
        summaryUrl += `&seasons=${seasons}`;
    }

    const summary = await makeAPIRequest(summaryUrl, 'GET', headers, null, userId);
    if (!summary.success || !Array.isArray(summary.data?.data)) {
        logActivity(userId, `⚠️ Scan: collections fetch failed (status=${summary.status} err=${summary.error || 'none'})`);
        return [];
    }

    const collections = [];
    for (const row of summary.data.data) {
        if (!row || row.count === 0) continue;
        const coll = row.collection;
        if (!coll) continue;
        if (coll.properties?.tiers?.includes('Loadout')) continue;
        if (DEFAULT_EXCLUDED_COLLECTIONS.has(coll.id)) continue;
        const type = coll.properties?.entity_types?.[0] || 'card';
        if (type !== 'card') continue;
        if (!collections.some(c => c.id === coll.id)) collections.push({ id: coll.id });
    }
    const scanLabel = categoryId !== 1 ? ` [cat ${categoryId}]` : '';
    logActivity(userId, `🔍 Scan${scanLabel}: ${collections.length} collections`);

    for (const coll of collections) {
        if (!user.isActive) break;
        const marketTpl = skipMarketTemplates ? {} : await fetchMarketTemplatesForCollection(userId, headers, coll.id);
        const itemsUrl = `${BASE_URL_COLLECTIONS}/collections/${coll.id}/users/${user.userId}/owned2`;
        const items = await makeAPIRequest(itemsUrl, 'GET', headers, null, userId);
        if (!items.success) { logActivity(userId, `⚠️ Items fail coll ${coll.id}`); continue; }
        const cards = items.data?.data?.cards || [];
        for (const item of cards) {
            if (item.status !== 'available') continue;
            if (!item.id || item.mintNumber == null) continue;
            const templateId = item.cardTemplateId || null;
            const mkt = templateId != null ? marketTpl[templateId] : null;
            const minted = mkt?.minted || null;
            const rating = Number(item.rating) || 0;
            collected.push({
                id: item.id, mintNumber: Number(item.mintNumber) || 0,
                rating, templateId, collectionId: coll.id, minted,
            });
            if (templateId && minted) {
                recordTemplateCirculation(templateId, minted);
                mergeCollectionObservation(coll.id, minted, rating);
            }
        }
    }
    const seen = new Set();
    const unique = [];
    for (const it of collected) { if (!seen.has(it.id)) { seen.add(it.id); unique.push(it); } }
    logActivity(userId, `🔍 Scan${scanLabel}: ${unique.length} unique available cards`);
    return unique;
}

async function listCardOnMarket(userId, cardId, price) {
    const user = userData[userId];
    if (!user?.jwtToken) return false;
    if (!BASE_URL_MARKET) return false;
    const r = await makeAPIRequest(`${BASE_URL_MARKET}/market/list`, 'POST',
        { 'Content-Type': 'application/json', 'x-user-jwt': user.jwtToken },
        { id: cardId, type: 'card', price: String(price) }, userId, { maxRetries: 0 });
    return r.success;
}

async function listCardsOnMarket(userId, cards, label) {
    const user = userData[userId];
    if (!user?.jwtToken || !cards?.length) return { listed: 0, failed: 0 };
    const aggression = getUserAggression(user);
    const delay = Math.max(Number(globalListingConfig.delayMs) || 2400, 100);
    const period = new Date().toISOString().slice(0, 10);
    let listed = 0, failed = 0;

    for (let i = 0; i < cards.length; i++) {
        if (!user.isActive) { logActivity(userId, `⏸ Inactive mid-list [${label}]`); break; }
        const card = cards[i];
        const info = calculateListingPrice(card, userId, { aggression, pricingPeriod: period });
        logActivity(userId,
            `💵 [${label} ${i + 1}/${cards.length}] ${card.id} M=${card.mintNumber} R=${card.rating.toFixed(2)} ` +
            `→ ${info.price.toFixed(2)} (${info.tier}, CL=${info.circulationUsed}/${info.circulationSource})`);
        const ok = await listCardOnMarket(userId, card.id, info.price);
        if (ok) listed++; else failed++;
        if (i < cards.length - 1) await sleep(delay);
    }
    logActivity(userId, `📋 [${label}] Listed ${listed}, failed ${failed} of ${cards.length}`);
    return { listed, failed };
}

async function scanAndListCards(userId) {
    const user = userData[userId];
    if (!user?.jwtToken) { logActivity(userId, '❌ no JWT'); return { scanned: 0, listed: 0, failed: 0 }; }
    logActivity(userId, '🔍 Scan+list start (manual / all cards)');
    const cards = await scanUserCards(userId);
    await saveCirculationCache();
    if (!cards.length) { logActivity(userId, 'ℹ️ Nothing to list'); return { scanned: 0, listed: 0, failed: 0 }; }
    const { listed, failed } = await listCardsOnMarket(userId, cards, 'all');
    return { scanned: cards.length, listed, failed };
}

// ============================================================
// 💼 BUNDLE CREATOR
// ============================================================
function shuffleInPlace(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}
function shuffleTwice(arr) {
    return shuffleInPlace(shuffleInPlace([...arr]));
}

function extractBundleIdFromCreateResponse(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const tryPath = (obj, path) => {
        let cur = obj;
        for (const p of path) {
            if (cur == null || typeof cur !== 'object') return null;
            cur = cur[p];
        }
        return cur;
    };
    const paths = [
        ['data', 'id'],
        ['id'],
        ['data', 'bundle', 'id'],
        ['bundle', 'id'],
        ['data', 'data', 'id'],
        ['data', 'data', 'bundle', 'id'],
    ];
    for (const p of paths) {
        const v = tryPath(raw, p);
        if (v != null && (typeof v === 'number' || typeof v === 'string')) return v;
    }
    return null;
}

async function scanUserOwnBundles(userId) {
    const user = userData[userId];
    if (!user?.jwtToken || !BASE_URL_MARKET) return null;
    const headers = { 'Content-Type': 'application/json', 'x-user-jwt': user.jwtToken };
    const out = [];
    let page = 1;

    while (page <= BUNDLE_SCAN_MAX_PAGES) {
        const url = `${BASE_URL_MARKET}/bundles?page=${page}`;
        let r = await makeAPIRequest(url, 'GET', headers, null, userId);

        if (!r.success && r.status === 401 && await refreshToken(userId)) {
            const h2 = { 'Content-Type': 'application/json', 'x-user-jwt': userData[userId].jwtToken };
            r = await makeAPIRequest(url, 'GET', h2, null, userId);
        }

        if (!r.success) {
            if (page === 1) {
                logActivity(userId, `❌ Bundle scan failed on first page: ${r.error || r.status}`);
                return null;
            }
            logActivity(userId, `⚠️ Bundle scan page ${page} failed: ${r.error}`);
            break;
        }

        let payload = r.data;
        if (payload?.data && (payload.data.bundles || payload.data.total !== undefined)) payload = payload.data;
        else if (payload?.data?.data && (payload.data.data.bundles || payload.data.data.total !== undefined)) payload = payload.data.data;

        const list = Array.isArray(payload?.bundles) ? payload.bundles : [];
        for (const b of list) {
            if (!b?.id) continue;
            out.push({
                id: b.id,
                name: b.name || '',
                entityCount: b.entityCount ?? null,
                status: b.status || '',
                marketId: b.market?.id ?? null,
                marketPrice: b.market?.price ?? null,
                userId: b.userId ?? null,
            });
        }

        if (list.length < BUNDLE_SCAN_PAGE_SIZE) break;
        page++;
        await sleep(300);
    }
    logActivity(userId, `🔍 Own-bundle scan: ${out.length} bundle(s)`);
    return out;
}

async function createOneBundle(userId, name, cardIds) {
    const user = userData[userId];
    if (!user?.jwtToken || !BASE_URL_MARKET) return { success: false, error: 'no jwt / no market url' };
    const headers = { 'Content-Type': 'application/json', 'x-user-jwt': user.jwtToken };
    const body = { name, cardIds };
    const r = await makeAPIRequest(`${BASE_URL_MARKET}/bundles/create`, 'POST', headers, body, userId, { maxRetries: 0 });

    if (r.success) {
        return { success: true, raw: r.data, bundleId: extractBundleIdFromCreateResponse(r.data) };
    }
    if (r.status === 401 && await refreshToken(userId)) {
        return createOneBundle(userId, name, cardIds);
    }
    return { success: false, error: r.error || r.responseData?.message || 'create failed' };
}

async function listBundleOnMarket(userId, bundleId, price) {
    const user = userData[userId];
    if (!user?.jwtToken || !BASE_URL_MARKET) return false;
    const r = await makeAPIRequest(`${BASE_URL_MARKET}/market/list`, 'POST',
        { 'Content-Type': 'application/json', 'x-user-jwt': user.jwtToken },
        { id: bundleId, type: 'bundle', price: String(price) }, userId, { maxRetries: 0 });
    return r.success;
}

// ------------------------------------------------------------
// Cat73 flow
// ------------------------------------------------------------
async function runCat73Flow(userId) {
    const user = userData[userId];
    logActivity(userId, `💼 Cat73 (KL exclusive bulk, categoryId=${CAT73_CATEGORY_ID}) start`);

    const cards73 = await scanUserCards(userId, {
        categoryId: CAT73_CATEGORY_ID,
        seasons: null,
        skipMarketTemplates: true,
    });
    if (!cards73.length) {
        logActivity(userId, `ℹ️ Cat73: no cards found in categoryId=${CAT73_CATEGORY_ID} — done`);
        return { success: true, cardsScanned: 0, bundlesBefore: null, slotsFree: null, bundlesCreated: 0, bundlesListed: 0 };
    }
    logActivity(userId, `🔍 Cat73: ${cards73.length} card(s) in categoryId=${CAT73_CATEGORY_ID}`);

    const bundlesBefore = await scanUserOwnBundles(userId);
    if (bundlesBefore === null) {
        logActivity(userId, '❌ Cat73: bundle scan failed — aborting (won\'t risk over-creating)');
        return { success: false, reason: 'bundle scan failed', cardsScanned: cards73.length, bundlesCreated: 0, bundlesListed: 0 };
    }
    const slotsFree = Math.max(0, BUNDLE_MAX_PER_USER - bundlesBefore.length);
    logActivity(userId, `📦 Cat73: bundles owned ${bundlesBefore.length}/${BUNDLE_MAX_PER_USER} → free slots ${slotsFree}`);
    if (slotsFree === 0) {
        logActivity(userId, 'ℹ️ Cat73: no free bundle slots — skipping creation');
        return { success: true, cardsScanned: cards73.length, bundlesBefore: bundlesBefore.length, slotsFree, bundlesCreated: 0, bundlesListed: 0 };
    }

    const shuffled = shuffleTwice(cards73.map(c => c.id));
    const maxFromCards = Math.floor(shuffled.length / CAT73_BUNDLE_CARDS);
    const toCreate = Math.min(slotsFree, maxFromCards);
    if (toCreate === 0) {
        logActivity(userId, `ℹ️ Cat73: not enough cards (${cards73.length}) for bundle(s) of ${CAT73_BUNDLE_CARDS}`);
        return { success: true, cardsScanned: cards73.length, bundlesBefore: bundlesBefore.length, slotsFree, bundlesCreated: 0, bundlesListed: 0 };
    }
    logActivity(userId, `🎲 Cat73: will create ${toCreate} bundle(s) of ${CAT73_BUNDLE_CARDS} cards, name="${CAT73_BUNDLE_NAME}"`);

    const createdBundleIds = [];
    let createSuccessCount = 0;
    for (let i = 0; i < toCreate; i++) {
        if (!user.isActive) { logActivity(userId, '⏸ Cat73: inactive mid-create'); break; }
        const slice = shuffled.slice(i * CAT73_BUNDLE_CARDS, (i + 1) * CAT73_BUNDLE_CARDS);
        const res = await createOneBundle(userId, CAT73_BUNDLE_NAME, slice);
        if (res.success) {
            createSuccessCount++;
            if (res.bundleId != null) createdBundleIds.push(res.bundleId);
            logActivity(userId, `✅ Cat73 bundle ${i + 1}/${toCreate} created (id=${res.bundleId ?? '∅'}, cards: ${slice.join(',')})`);
        } else {
            logActivity(userId, `❌ Cat73 bundle ${i + 1}/${toCreate} failed: ${res.error}`);
        }
        if (i < toCreate - 1) await sleep(BUNDLE_CREATE_DELAY_MS);
    }

    let targetIds = [...createdBundleIds];
    if (targetIds.length < createSuccessCount) {
        logActivity(userId, `🔍 Cat73: only ${targetIds.length}/${createSuccessCount} create-response IDs extracted — re-scanning to fill gaps`);
        await sleep(1500);
        const rescanned = await scanUserOwnBundles(userId);
        if (rescanned) {
            const extra = rescanned
                .filter(b => b.status !== 'market' && b.name === CAT73_BUNDLE_NAME)
                .map(b => b.id)
                .filter(id => !targetIds.includes(id));
            logActivity(userId, `🔍 Cat73: re-scan found ${extra.length} additional unlisted "${CAT73_BUNDLE_NAME}" bundle(s)`);
            targetIds = targetIds.concat(extra);
        }
    }

    let bundlesListed = 0;
    if (!targetIds.length) {
        logActivity(userId, 'ℹ️ Cat73: no bundle IDs to list');
    } else {
        logActivity(userId, `📋 Cat73: listing ${targetIds.length} bundle(s) at ${CAT73_LISTING_PRICE}`);
        for (let i = 0; i < targetIds.length; i++) {
            if (!user.isActive) { logActivity(userId, '⏸ Cat73: inactive mid-list'); break; }
            const id = targetIds[i];
            const ok = await listBundleOnMarket(userId, id, CAT73_LISTING_PRICE);
            if (ok) bundlesListed++;
            logActivity(userId, `${ok ? '✅' : '❌'} Cat73 list bundle ${id} @ ${CAT73_LISTING_PRICE} (${i + 1}/${targetIds.length})`);
            if (i < targetIds.length - 1) await sleep(BUNDLE_LISTING_DELAY_MS);
        }
    }

    user.bundlesCreated = (user.bundlesCreated || 0) + createSuccessCount;
    logActivity(userId, `💼 Cat73 done — bundlesCreated=${createSuccessCount}, bundlesListed=${bundlesListed}`);
    return {
        success: true,
        cardsScanned: cards73.length,
        bundlesBefore: bundlesBefore.length,
        slotsFree,
        bundlesCreated: createSuccessCount,
        bundlesListed,
    };
}

// ------------------------------------------------------------
// Cat1 flow
// ------------------------------------------------------------
async function runCat1Flow(userId, opts = {}) {
    const user = userData[userId];
    logActivity(userId, '💼 Cat1 bundle creator start');

    const allCards = await scanUserCards(userId);
    await saveCirculationCache();
    if (!allCards.length) {
        logActivity(userId, 'ℹ️ Cat1: no cards found — done');
        return { success: true, scannedCards: 0, cardsListed: 0, bundlesCreated: 0, bundlesListed: 0 };
    }
    const lowMint  = allCards.filter(c => c.mintNumber <= CARD_MINT_THRESHOLD);
    const highMint = allCards.filter(c => c.mintNumber >  CARD_MINT_THRESHOLD);
    logActivity(userId, `📊 Cat1 split: ${lowMint.length} <=${CARD_MINT_THRESHOLD} / ${highMint.length} >${CARD_MINT_THRESHOLD}`);

    let listResult = { listed: 0, failed: 0 };
    if (lowMint.length) {
        logActivity(userId, `📋 Cat1: listing ${lowMint.length} low-mint card(s)...`);
        listResult = await listCardsOnMarket(userId, lowMint, 'low-mint');
    } else {
        logActivity(userId, `ℹ️ Cat1: no <=${CARD_MINT_THRESHOLD} cards to list`);
    }

    const bundlesBefore = await scanUserOwnBundles(userId);
    if (bundlesBefore === null) {
        logActivity(userId, '❌ Cat1: bundle scan failed — aborting (won\'t risk over-creating)');
        return { success: false, reason: 'bundle scan failed', cardsListed: listResult.listed };
    }
    const observedCount = bundlesBefore.length;
    const floor = Number(opts.bundleCountFloor) || 0;
    const effectiveCount = Math.max(observedCount, floor);
    const slotsFree = Math.max(0, BUNDLE_MAX_PER_USER - effectiveCount);
    const floorNote = effectiveCount > observedCount ? ` (floor ${effectiveCount})` : '';
    logActivity(userId, `📦 Cat1: bundles owned ${observedCount}/${BUNDLE_MAX_PER_USER}${floorNote} → free slots ${slotsFree}`);

    let bundlesCreated = 0;
    if (slotsFree === 0) {
        logActivity(userId, 'ℹ️ Cat1: no free bundle slots — skipping creation');
    } else if (highMint.length < BUNDLE_CARDS_PER_BUNDLE) {
        logActivity(userId, `ℹ️ Cat1: not enough >${CARD_MINT_THRESHOLD} cards (${highMint.length}) for bundle of ${BUNDLE_CARDS_PER_BUNDLE}`);
    } else {
        const shuffled = shuffleTwice(highMint.map(c => c.id));
        const maxFromCards = Math.floor(shuffled.length / BUNDLE_CARDS_PER_BUNDLE);
        const toCreate = Math.min(slotsFree, maxFromCards);
        logActivity(userId, `🎲 Cat1: will create ${toCreate} bundle(s) of ${BUNDLE_CARDS_PER_BUNDLE} cards, name="${BUNDLE_NAME}"`);

        for (let i = 0; i < toCreate; i++) {
            if (!user.isActive) { logActivity(userId, '⏸ Cat1: inactive mid-create'); break; }
            const slice = shuffled.slice(
                i * BUNDLE_CARDS_PER_BUNDLE,
                (i + 1) * BUNDLE_CARDS_PER_BUNDLE
            );
            const res = await createOneBundle(userId, BUNDLE_NAME, slice);
            if (res.success) {
                bundlesCreated++;
                logActivity(userId, `✅ Cat1 bundle ${i + 1}/${toCreate} created (cards: ${slice.join(',')})`);
            } else {
                logActivity(userId, `❌ Cat1 bundle ${i + 1}/${toCreate} failed: ${res.error}`);
            }
            if (i < toCreate - 1) await sleep(BUNDLE_CREATE_DELAY_MS);
        }
    }

    let bundlesListed = 0;
    if (bundlesCreated > 0) {
        await sleep(1500);
        const bundlesAfter = await scanUserOwnBundles(userId);
        if (bundlesAfter === null) {
            logActivity(userId, '⚠️ Cat1: re-scan failed — cannot list new bundles');
        } else {
            const available = bundlesAfter.filter(b => b.status !== 'market');
            logActivity(userId, `🔎 Cat1 available (unlisted) bundles: ${available.length}`);
            for (let i = 0; i < available.length; i++) {
                if (!user.isActive) { logActivity(userId, '⏸ Cat1: inactive mid-list-bundles'); break; }
                const b = available[i];
                const ok = await listBundleOnMarket(userId, b.id, BUNDLE_LISTING_PRICE);
                if (ok) bundlesListed++;
                logActivity(userId, `${ok ? '✅' : '❌'} Cat1 list bundle ${b.id} @ ${BUNDLE_LISTING_PRICE} (${i + 1}/${available.length})`);
                if (i < available.length - 1) await sleep(BUNDLE_LISTING_DELAY_MS);
            }
        }
    }

    user.bundlesCreated = (user.bundlesCreated || 0) + bundlesCreated;
    logActivity(userId,
        `💼 Cat1 done — cardsListed=${listResult.listed}/${lowMint.length}, ` +
        `bundlesCreated=${bundlesCreated}, bundlesListed=${bundlesListed}`);
    return {
        success: true,
        scannedCards: allCards.length,
        lowMintCards: lowMint.length,
        highMintCards: highMint.length,
        cardsListed: listResult.listed,
        bundlesBefore: observedCount,
        slotsFree,
        bundlesCreated,
        bundlesListed,
    };
}

async function executeBundleCreator(userId) {
    const user = userData[userId];
    if (!user) return { skipped: true, reason: 'no user' };
    if (user._bundleCreatorRunning) {
        logActivity(userId, '⚠️ Bundle creator already running — skipping overlap');
        return { skipped: true, reason: 'already running' };
    }
    if (!user.jwtToken) {
        logActivity(userId, '❌ Bundle creator: no JWT');
        return { skipped: true, reason: 'no jwt' };
    }
    if (!BASE_URL_MARKET || !BASE_URL_COLLECTIONS) {
        logActivity(userId, '❌ Bundle creator: missing URL env vars');
        return { skipped: true, reason: 'missing urls' };
    }

    user._bundleCreatorRunning = true;
    try {
        logActivity(userId, '💼 Bundle creator (combined: cat73 → cat1) start');

        let cat73 = null;
        try { cat73 = await runCat73Flow(userId); }
        catch (e) {
            logActivity(userId, `❌ Cat73 flow error: ${e.message}`);
            cat73 = { success: false, error: e.message };
        }

        const cat73Created  = Number(cat73?.bundlesCreated) || 0;
        const cat73Before   = (cat73 && cat73.bundlesBefore != null) ? Number(cat73.bundlesBefore) : null;
        const bundleCountFloor = (cat73Before != null) ? (cat73Before + cat73Created) : null;

        logActivity(userId, `⏳ Cat73 done — waiting ${CAT73_POST_FLOW_WAIT_MS}ms before cat1 (bundle-count sync)`);
        await sleep(CAT73_POST_FLOW_WAIT_MS);

        let cat1 = null;
        try { cat1 = await runCat1Flow(userId, { bundleCountFloor }); }
        catch (e) {
            logActivity(userId, `❌ Cat1 flow error: ${e.message}`);
            cat1 = { success: false, error: e.message };
        }

        user.bundleCreatorsDone = (user.bundleCreatorsDone || 0) + 1;
        logActivity(userId, '💼 Bundle creator (combined) done');
        return { success: true, cat73, cat1 };
    } finally {
        user._bundleCreatorRunning = false;
    }
}

async function executeCat1Only(userId) {
    const user = userData[userId];
    if (!user) return { skipped: true, reason: 'no user' };
    if (user._bundleCreatorRunning) {
        logActivity(userId, '⚠️ Bundle creator already running — skipping overlap');
        return { skipped: true, reason: 'already running' };
    }
    if (!user.jwtToken) return { skipped: true, reason: 'no jwt' };
    if (!BASE_URL_MARKET || !BASE_URL_COLLECTIONS) return { skipped: true, reason: 'missing urls' };

    user._bundleCreatorRunning = true;
    try {
        const res = await runCat1Flow(userId);
        user.bundleCreatorsDone = (user.bundleCreatorsDone || 0) + 1;
        return res;
    } finally {
        user._bundleCreatorRunning = false;
    }
}

async function executeCat73Only(userId) {
    const user = userData[userId];
    if (!user) return { skipped: true, reason: 'no user' };
    if (user._bundleCreatorRunning) {
        logActivity(userId, '⚠️ Bundle creator already running — skipping overlap');
        return { skipped: true, reason: 'already running' };
    }
    if (!user.jwtToken) return { skipped: true, reason: 'no jwt' };
    if (!BASE_URL_MARKET || !BASE_URL_COLLECTIONS) return { skipped: true, reason: 'missing urls' };

    user._bundleCreatorRunning = true;
    try {
        const res = await runCat73Flow(userId);
        user.bundleCreatorsDone = (user.bundleCreatorsDone || 0) + 1;
        return res;
    } finally {
        user._bundleCreatorRunning = false;
    }
}

// ============================================================
// 🔁 CONTINUOUS OPS
// ============================================================
function startContinuousOperations() {
    setInterval(async () => {
        for (const userId of Object.keys(userData)) {
            const u = userData[userId];
            if (!u.isActive || !isWithinActiveWindow(userId)) continue;
            if (!u.nextSpinTime || new Date() >= new Date(u.nextSpinTime)) await executeSpin(userId);
        }
    }, 30000);
    setInterval(async () => {
        for (const userId of Object.keys(userData)) {
            if (isWithinActiveWindow(userId) && userData[userId].isActive) await checkFunds(userId);
        }
    }, 60 * 60 * 1000);
}
function startScheduledTasks() { scheduleDailyPlanForAllUsers(); }

// ============================================================
// 🌐 MIDDLEWARE + STATIC (must come BEFORE routes)
// ============================================================
app.use(express.json());
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));
console.log(`📁 Serving static files from: ${PUBLIC_DIR}`);

app.get('/', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'), (err) => {
        if (err) {
            console.error('❌ index.html not found at', path.join(PUBLIC_DIR, 'index.html'));
            res.status(500).send('index.html missing on server — check deployment');
        }
    });
});

// ============================================================
// 🌐 API ROUTES
// ============================================================
app.get('/api/users', (req, res) => res.json(safeUsersSnapshot()));
app.get('/api/activity', (req, res) => res.json(activityLogs.slice(0, parseInt(req.query.limit) || 100)));
app.get('/api/user/:userId/activity', (req, res) => {
    const u = userData[req.params.userId];
    if (!u) return res.status(404).json({ error: 'not found' });
    res.json(u.logs.slice(0, parseInt(req.query.limit) || 50));
});
app.get('/api/debug-logs', (req, res) => res.json(debugLogs.slice(0, parseInt(req.query.limit) || 50)));

app.get('/api/proxy-status', async (req, res) => {
    const probe = PROXY_ENABLED ? await probeProxy() : { success: false, disabled: true };
    res.json({
        enabled: PROXY_ENABLED,
        url: PROXY_ENABLED ? redactProxyUrl(PROXY_URL) : null,
        timeoutMs: PROXY_TIMEOUT_MS,
        maxRetries: PROXY_MAX_RETRIES,
        proxyDepsAvailable,
        probe,
    });
});

app.get('/api/test-collections/:userId', async (req, res) => {
    const userId = req.params.userId;
    const user = userData[userId];
    if (!user?.jwtToken) return res.status(400).json({ error: 'No JWT for user' });
    if (!BASE_URL_COLLECTIONS) return res.status(500).json({
        error: 'BASE_URL_COLLECTIONS empty', KOLEX_API_BASE, BASE_URL_SPRAY,
        hint: 'Set BASE_URL_COLLECTIONS env var to the API root (e.g. https://api.kolex.gg/api/v1)',
    });
    const url = `${BASE_URL_COLLECTIONS}/collections/users/${user.userId}/user-summary?categoryId=1&seasons=2026`;
    const result = await makeAPIRequest(url, 'GET', { 'x-user-jwt': user.jwtToken }, null, userId);
    res.json({ url, success: result.success, status: result.status, error: result.error,
        isProxyError: result.isProxyError,
        dataPreview: result.data ? JSON.stringify(result.data).slice(0, 800) : null });
});

app.get('/api/spinner-config', (req, res) => res.json(globalSpinnerConfig));
app.post('/api/spinner-config', async (req, res) => {
    const { spinnerId, packIds, autoFetch } = req.body;
    if (spinnerId !== undefined && spinnerId !== '') globalSpinnerConfig.spinnerId = parseInt(spinnerId) || globalSpinnerConfig.spinnerId;
    if (packIds !== undefined) {
        if (typeof packIds === 'string') globalSpinnerConfig.packIds = packIds.split(',').map(x => parseInt(x.trim())).filter(x => !isNaN(x));
        else if (Array.isArray(packIds)) globalSpinnerConfig.packIds = packIds.map(x => parseInt(x)).filter(x => !isNaN(x));
    }
    if (autoFetch !== undefined) globalSpinnerConfig.autoFetch = !!autoFetch;
    await saveSpinnerConfig();
    logActivity('system', `⚙️ Spinner config saved`);
    res.json({ success: true, config: globalSpinnerConfig });
});

app.post('/api/spinner-check', async (req, res) => {
    let userId = req.body?.userId;
    if (!userId) userId = Object.keys(userData).find(id => userData[id].jwtToken);
    if (!userId) return res.status(400).json({ error: 'No user with JWT' });
    if (!userData[userId]?.jwtToken) return res.status(400).json({ error: 'No JWT for user' });
    const success = await fetchAndUpdateSpinnerInfo(userId, true);
    res.json({ success, config: globalSpinnerConfig, usedUserId: userId });
});

app.post('/api/user/:userId/spinner-check', async (req, res) => {
    const userId = req.params.userId;
    if (!userData[userId]) return res.status(404).json({ error: 'User not found' });
    if (!userData[userId].jwtToken) return res.status(400).json({ error: 'No JWT for user' });
    const success = await fetchAndUpdateSpinnerInfo(userId, true);
    res.json({ success, config: globalSpinnerConfig, usedUserId: userId });
});

app.get('/api/listing-config', (req, res) => res.json(globalListingConfig));
app.post('/api/listing-config', async (req, res) => {
    if (req.body.delayMs !== undefined) globalListingConfig.delayMs = Math.max(parseInt(req.body.delayMs) || 2400, 100);
    try { await fs.writeFile('listing-config.json', JSON.stringify(globalListingConfig, null, 2)); } catch {}
    logActivity('system', `⚙️ Listing delay = ${globalListingConfig.delayMs}ms`);
    res.json({ success: true, config: globalListingConfig });
});

app.get('/api/circulation-cache', (req, res) => res.json({
    templateCount: Object.keys(templateCirculationCache).length,
    collectionCount: Object.keys(collectionCirculationProfiles).length,
    collectionProfiles: collectionCirculationProfiles,
}));

app.get('/api/export/user-jwt', (req, res) => {
    const out = {};
    for (const [id, u] of Object.entries(userData)) out[id] = { userId: id, jwtToken: u.jwtToken || '' };
    res.json(out);
});
app.get('/api/export/full-data', (req, res) => {
    const out = [];
    for (const [id, u] of Object.entries(userData)) out.push({
        nick: u.userNick || '', userId: id,
        funds: u.lastFunds || 0, coronas: u.lastCoronas || 0, usd: u.lastUsd || '0', jwtToken: u.jwtToken || ''
    });
    res.json(out);
});

app.post('/api/user/:userId/refresh', async (req, res) => res.json({ success: await refreshToken(req.params.userId) }));
app.post('/api/user/:userId/spin', async (req, res) => res.json({ success: !!(await executeSpin(req.params.userId)) }));
app.post('/api/user/:userId/claim-achievements', async (req, res) => res.json({ success: true, claimed: await claimAchievements(req.params.userId) }));
app.post('/api/user/:userId/check-funds', async (req, res) => res.json({ success: true, funds: await checkFunds(req.params.userId) }));

app.post('/api/user/:userId/scan-list', async (req, res) => {
    const userId = req.params.userId;
    if (!userData[userId]) return res.status(404).json({ error: 'User not found' });
    if (!userData[userId].jwtToken) return res.status(400).json({ error: 'No JWT' });
    try { res.json({ success: true, ...(await scanAndListCards(userId)) }); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/:userId/create-bundles', async (req, res) => {
    const userId = req.params.userId;
    if (!userData[userId]) return res.status(404).json({ error: 'User not found' });
    if (!userData[userId].jwtToken) return res.status(400).json({ error: 'No JWT' });
    try { res.json(await executeBundleCreator(userId)); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/:userId/create-bundles-cat1', async (req, res) => {
    const userId = req.params.userId;
    if (!userData[userId]) return res.status(404).json({ error: 'User not found' });
    if (!userData[userId].jwtToken) return res.status(400).json({ error: 'No JWT' });
    try { res.json(await executeCat1Only(userId)); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/:userId/create-bundles-73', async (req, res) => {
    const userId = req.params.userId;
    if (!userData[userId]) return res.status(404).json({ error: 'User not found' });
    if (!userData[userId].jwtToken) return res.status(400).json({ error: 'No JWT' });
    try { res.json(await executeCat73Only(userId)); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// 🚀 START
// ============================================================
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    initializeApp();
});