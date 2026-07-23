/**
 * Demo wiring: dash.js playback + per-segment C2PA verification + the
 * Content Credentials overlay.
 */
(function () {
    'use strict';

    var SAMPLE_BASE = 'samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/';
    var MPD_URL = new URL(SAMPLE_BASE + 'stream.mpd', window.location.href).href;
    var MANIFEST_JSON_URL = SAMPLE_BASE + 'example_c2pa_manifest.json';
    var MERKLE_MANIFEST_URL = SAMPLE_BASE + 'video_merkle_manifest.json';
    var FIRST_SEGMENT = 803347;
    var LAST_SEGMENT = 803366;
    var SEGMENT_DURATION = 128000 / 12288; // seconds

    var COSE_ALGS = { '-7': 'ES256', '-35': 'ES384', '-36': 'ES512', '-37': 'PS256', '-38': 'PS384', '-39': 'PS512', '-8': 'EdDSA' };

    var video = document.getElementById('video');
    var results = {};          // segmentId -> verification result
    var tamperNext = false;
    var exampleManifestParams = null;
    var merkleManifest = null;
    var merkleManifestReady = C2PAMerkle.loadManifest(MERKLE_MANIFEST_URL).then(function (json) {
        merkleManifest = json;
    }).catch(function () { /* merkle panel section stays empty */ });
    var activeSegment = null;
    var player;

    /* ---------------------------------------------------------------- *
     *  Verification plumbing
     * ---------------------------------------------------------------- */

    function segmentIdFromUrl(url) {
        var m = /seg_(\d+)\.m4s/.exec(url);
        return m ? parseInt(m[1], 10) : null;
    }

    // Flips one byte inside the mdat payload so the continuity check fails.
    function tamper(u8) {
        var pos = 0;
        while (pos + 8 <= u8.length) {
            var size = (u8[pos] << 24 >>> 0) + (u8[pos + 1] << 16) + (u8[pos + 2] << 8) + u8[pos + 3];
            var type = String.fromCharCode(u8[pos + 4], u8[pos + 5], u8[pos + 6], u8[pos + 7]);
            if (type === 'mdat') {
                var target = pos + 8 + Math.floor((size - 8) / 2);
                u8[target] = u8[target] ^ 0xff;
                return true;
            }
            pos += size;
        }
        return false;
    }

    function onSegmentResponse(response) {
        var segmentId = segmentIdFromUrl(response.url || '');
        if (segmentId === null || !response.data) {
            return Promise.resolve(response);
        }
        var u8 = new Uint8Array(response.data);
        var tampered = false;
        if (tamperNext) {
            tamperNext = false;
            tampered = tamper(u8);
            updateTamperButton();
        }
        setResult(segmentId, { status: 'verifying', tampered: tampered });
        return Promise.all([
            C2PA.verifySegment(u8),
            merkleManifestReady.then(function () {
                return merkleManifest ? C2PAMerkle.verifySegment(merkleManifest, segmentId, u8) : null;
            })
        ]).then(function (both) {
            var result = both[0];
            result.merkle = both[1];
            result.tampered = tampered;
            result.verifiedAt = new Date();
            setResult(segmentId, result);
            return response;
        }).catch(function (e) {
            setResult(segmentId, { status: 'error', error: String(e) });
            return response;
        });
    }

    function setResult(segmentId, result) {
        results[segmentId] = result;
        renderStrip();
        if (segmentId === activeSegment || activeSegment === null) {
            renderPanel();
        }
        renderBadge();
    }

    /* ---------------------------------------------------------------- *
     *  UI rendering
     * ---------------------------------------------------------------- */

    function el(id) { return document.getElementById(id); }

    function statusOf(segmentId) {
        var r = results[segmentId];
        return r ? r.status : 'pending';
    }

    function currentSegment() {
        var t = video.currentTime || 0;
        var id = FIRST_SEGMENT + Math.floor(t / SEGMENT_DURATION + 1e-6);
        return Math.max(FIRST_SEGMENT, Math.min(LAST_SEGMENT, id));
    }

    function renderBadge() {
        var seg = activeSegment || FIRST_SEGMENT;
        var status = statusOf(seg);
        var badge = el('crBadge');
        badge.className = 'cr-badge ' + status;
        el('crBadgeText').textContent =
            status === 'valid' ? 'Content Credentials' :
            status === 'invalid' ? 'Credentials invalid' :
            status === 'verifying' ? 'Verifying…' : 'Content Credentials';
    }

    function renderStrip() {
        var strip = el('segStrip');
        var html = '';
        for (var id = FIRST_SEGMENT; id <= LAST_SEGMENT; id++) {
            var status = statusOf(id);
            var cls = 'seg ' + status + (id === activeSegment ? ' active' : '');
            var r = results[id];
            var title = 'seg_' + id + '.m4s — ' + status + (r && r.tampered ? ' (tampered)' : '');
            html += '<div class="' + cls + '" title="' + title + '" data-id="' + id + '">' + (id === activeSegment ? '▶' : '') + '</div>';
        }
        strip.innerHTML = html;
    }

    function field(label, value) {
        if (!value) { return ''; }
        return '<div class="row"><div class="k">' + label + '</div><div class="v">' + value + '</div></div>';
    }

    function mono(v) { return '<span class="mono">' + v + '</span>'; }

    function renderPanel() {
        var seg = activeSegment || FIRST_SEGMENT;
        var r = results[seg];
        var banner = el('statusBanner');
        var body = el('panelBody');

        if (!r || r.status === 'pending') {
            banner.className = 'banner pending';
            banner.textContent = 'Waiting for segment ' + seg + '…';
        } else if (r.status === 'verifying') {
            banner.className = 'banner pending';
            banner.textContent = 'Verifying segment ' + seg + '…';
        } else if (r.status === 'valid') {
            banner.className = 'banner valid';
            banner.innerHTML = '✓ Segment ' + seg + ' verified — continuity token matches';
        } else if (r.status === 'invalid') {
            banner.className = 'banner invalid';
            banner.innerHTML = '✖ Segment ' + seg + ' FAILED verification' + (r.tampered ? ' (byte was tampered in transit)' : '');
        } else {
            banner.className = 'banner invalid';
            banner.textContent = 'Segment ' + seg + ': ' + (r.error || 'no C2PA manifest found');
        }

        var m = r && r.manifest;
        var html = '';
        if (m) {
            var author = m.creativeWork && m.creativeWork.author && m.creativeWork.author[0] && m.creativeWork.author[0].name;
            var gen = m.claim && m.claim.claim_generator_info && m.claim.claim_generator_info[0];
            html += '<h3>Content Credentials</h3>';
            html += field('Title', m.claim && m.claim['dc:title']);
            html += field('Produced by', author);
            html += field('Date', m.creativeWork && m.creativeWork.dateCreated);
            html += field('Claim generator', gen ? gen.name + ' ' + (gen.version || '') : null);
            if (m.signer) {
                html += field('Signed by', [m.signer.subject, m.signer.organization].filter(Boolean).join(', '));
                html += field('Cert issuer', m.signer.issuedBy);
                html += field('Signature alg', COSE_ALGS[String(m.signer.alg)] || m.signer.alg);
            }
            html += field('Assertions', m.assertionLabels.join(', '));
        }
        if (r && r.expected) {
            html += '<h3>Segment integrity (c2pa.IVHASH)</h3>';
            html += field('Segment ID', mono(r.segmentId));
            html += field('Continuity token', mono(r.expected));
            html += field('Computed token', mono(r.computed) + (r.status === 'valid' ? ' ✓' : ' ✖'));
            html += field('Derived IV', mono(r.iv));
            html += field('Bytes verified', r.bytesHashed.toLocaleString() + ' (moof+mdat) in ' + r.durationMs.toFixed(1) + ' ms');
            if (exampleManifestParams && r.segmentId === exampleManifestParams.segmentId) {
                var match = exampleManifestParams.continuityToken === r.expected &&
                            exampleManifestParams.certHash === (m && m.ivhash && m.ivhash.certHash);
                html += field('example_c2pa_manifest.json', match ? 'matches embedded manifest ✓' : 'differs from embedded manifest');
            }
        }
        if (r && r.merkle && r.merkle.status !== 'no-proof') {
            var mk = r.merkle;
            html += '<h3>Segment integrity (C2PA Merkle tree, §9.2.3 / A.5.4)</h3>';
            html += field('Leaf location', mono(mk.location) + ' of ' + merkleManifest.bmffHashAssertion.merkle[0].count);
            html += field('Leaf hash', mono(mk.leafHash));
            html += field('Proof length', mk.proofLength + ' sibling hash(es)');
            html += field('Expected root', mono(mk.expectedRoot));
            html += field('Reconstructed root', mono(mk.computedRoot) + (mk.status === 'valid' ? ' ✓' : ' ✖'));
        }
        body.innerHTML = html || '<p class="hint">Segment details appear here once the first segment is fetched.</p>';
    }

    function updateTamperButton() {
        var btn = el('tamperBtn');
        btn.textContent = tamperNext ? '⚠ Tampering next segment…' : '⚠ Tamper next segment';
        btn.classList.toggle('armed', tamperNext);
    }

    /* ---------------------------------------------------------------- *
     *  Manifest JSON viewer + reference cross-check
     * ---------------------------------------------------------------- */

    function findIvhashParams(node) {
        if (!node || typeof node !== 'object') { return null; }
        if (node.action === 'c2pa.IVHASH' && node.parameters) { return node.parameters; }
        var keys = Object.keys(node);
        for (var i = 0; i < keys.length; i++) {
            var found = findIvhashParams(node[keys[i]]);
            if (found) { return found; }
        }
        return null;
    }

    fetch(MANIFEST_JSON_URL)
        .then(function (r) { return r.json(); })
        .then(function (json) {
            exampleManifestParams = findIvhashParams(json);
        })
        .catch(function () { /* viewer link still works */ });

    el('manifestBtn').addEventListener('click', function () {
        var dlg = el('manifestDlg');
        var seg = activeSegment || FIRST_SEGMENT;
        var r = results[seg];
        var view = {
            segment: 'seg_' + seg + '.m4s',
            verification: r ? {
                status: r.status,
                expectedContinuityToken: r.expected,
                computedContinuityToken: r.computed,
                derivedIv: r.iv
            } : 'pending',
            merkleVerification: r && r.merkle ? {
                status: r.merkle.status,
                location: r.merkle.location,
                leafHash: r.merkle.leafHash,
                proofLength: r.merkle.proofLength,
                expectedRoot: r.merkle.expectedRoot,
                computedRoot: r.merkle.computedRoot
            } : 'pending',
            manifest: r && r.manifest ? {
                claim: r.manifest.claim && {
                    'dc:title': r.manifest.claim['dc:title'],
                    'dc:format': r.manifest.claim['dc:format'],
                    claim_generator: r.manifest.claim.claim_generator,
                    instanceID: r.manifest.claim.instanceID
                },
                creativeWork: r.manifest.creativeWork,
                ivhash: r.manifest.ivhash,
                signer: r.manifest.signer,
                assertions: r.manifest.assertionLabels
            } : null
        };
        el('manifestDump').textContent = JSON.stringify(view, function (k, v) {
            return v && v.buffer instanceof ArrayBuffer ? '<' + v.length + ' bytes>' : v;
        }, 2);
        dlg.showModal();
    });

    el('manifestClose').addEventListener('click', function () { el('manifestDlg').close(); });
    el('tamperBtn').addEventListener('click', function () {
        tamperNext = !tamperNext;
        updateTamperButton();
    });
    el('crBadge').addEventListener('click', function () {
        document.body.classList.toggle('panel-hidden');
    });

    /* ---------------------------------------------------------------- *
     *  Player
     * ---------------------------------------------------------------- */

    player = dashjs.MediaPlayer().create();
    player.addResponseInterceptor(onSegmentResponse);
    player.initialize(video, MPD_URL, true);
    player.on(dashjs.MediaPlayer.events.PLAYBACK_ENDED, function () {
        player.seek(0);
    });
    player.on(dashjs.MediaPlayer.events.ERROR, function (e) {
        if (Object.keys(results).length === 0) {
            var banner = el('statusBanner');
            banner.className = 'banner invalid';
            banner.textContent = 'Player error: ' + ((e.error && e.error.message) || e.error) +
                ' — playback needs H.264 (avc1) support.';
        }
    });

    el('dashVersion').textContent = 'dash.js v' + player.getVersion();

    video.addEventListener('timeupdate', function () {
        var seg = currentSegment();
        if (seg !== activeSegment) {
            activeSegment = seg;
            renderStrip();
            renderPanel();
            renderBadge();
        }
    });

    renderStrip();
    renderPanel();
    renderBadge();
})();
