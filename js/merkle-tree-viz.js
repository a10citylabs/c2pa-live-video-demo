/**
 * Live visual illustration of the C2PA Merkle tree (see js/merkle-core.js
 * and samples/.../Merkle-Proof-Video-Segment-Validation.md for the
 * underlying construction/verification algorithm this mirrors).
 *
 * Recomputes the full tree client-side from the per-segment leaf hashes
 * already present in video_merkle_manifest.json, lays it out leaves-up,
 * and highlights the leaf-to-root path (plus the sibling hashes consumed
 * at each level) for whichever segment is currently playing.
 */
(function (global) {
    'use strict';

    var core = global.C2PAMerkleCore;
    var SAMPLE_BASE = 'samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/';
    var MERKLE_MANIFEST_URL = SAMPLE_BASE + 'video_merkle_manifest.json';
    var FIRST_SEGMENT = 803347;
    var SEGMENT_DURATION = 128000 / 12288;

    var NODE_W = 74, NODE_H = 34, NODE_GAP_X = 14, LEVEL_H = 66, PAD = 20;

    function sha256(bytes) {
        return crypto.subtle.digest('SHA-256', bytes).then(function (d) { return new Uint8Array(d); });
    }
    function fromBase64(s) {
        var bin = atob(s);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
        return out;
    }
    function toBase64(u8) {
        var s = '';
        for (var i = 0; i < u8.length; i++) { s += String.fromCharCode(u8[i]); }
        return btoa(s);
    }
    function short(b64) { return b64.slice(0, 8) + '…'; }
    function el(tag, cls) {
        var e = document.createElement(tag);
        if (cls) { e.className = cls; }
        return e;
    }
    function addClass(elm) {
        for (var i = 1; i < arguments.length; i++) {
            if (arguments[i]) { elm.classList.add(arguments[i]); }
        }
    }

    var state = { rows: null, rowsB64: null, layout: null, segmentIds: null, root: null, manifestRoot: null };

    function computeLayout(rows) {
        var leafCount = rows[0].length;
        var spacing = NODE_W + NODE_GAP_X;
        var width = leafCount * spacing + PAD * 2;
        var xs = [];
        xs[0] = [];
        var i, level, j;
        for (i = 0; i < leafCount; i++) {
            xs[0][i] = PAD + (i + 0.5) * spacing;
        }
        for (level = 1; level < rows.length; level++) {
            xs[level] = [];
            var prev = xs[level - 1];
            for (j = 0; j < rows[level].length; j++) {
                var l = 2 * j, r = 2 * j + 1;
                xs[level][j] = (r < prev.length) ? (prev[l] + prev[r]) / 2 : prev[l];
            }
        }
        var height = rows.length * LEVEL_H + PAD * 2;
        var ys = [];
        for (level = 0; level < rows.length; level++) {
            ys[level] = height - PAD - level * LEVEL_H - NODE_H / 2;
        }
        return { xs: xs, ys: ys, width: width, height: height };
    }

    // Same walk as core.reconstructRoot, but recording each step instead of
    // hashing, so the illustration and the real verification agree exactly.
    function pathForLocation(rows, location) {
        var idx = location;
        var steps = [];
        for (var level = 0; level < rows.length - 1; level++) {
            var levelSize = rows[level].length;
            var hasSib = core.hasSiblingAt(idx, levelSize);
            var siblingIdx = hasSib ? (idx % 2 === 0 ? idx + 1 : idx - 1) : null;
            steps.push({ level: level, idx: idx, hasSibling: hasSib, siblingIdx: siblingIdx, side: idx % 2 === 0 ? 'left' : 'right' });
            idx = Math.floor(idx / 2);
        }
        return steps;
    }

    function buildTree() {
        return fetch(MERKLE_MANIFEST_URL).then(function (r) { return r.json(); }).then(function (manifest) {
            var segs = manifest.segments.slice().sort(function (a, b) { return a.location - b.location; });
            var leafHashes = segs.map(function (s) { return fromBase64(s.leafHash); });
            return core.buildMerkleRows(leafHashes, sha256).then(function (rows) {
                state.rows = rows;
                state.rowsB64 = rows.map(function (row) { return row.map(toBase64); });
                state.layout = computeLayout(rows);
                state.segmentIds = segs.map(function (s) { return s.segmentId; });
                state.manifestRoot = manifest.bmffHashAssertion.merkle[0].hashes[0];
                state.root = state.rowsB64[state.rowsB64.length - 1][0];
            });
        });
    }

    function render(containerId) {
        var container = document.getElementById(containerId);
        if (!container || !state.rows) { return; }
        container.innerHTML = '';

        var inner = el('div', 'merkle-tree-inner');
        inner.style.width = state.layout.width + 'px';
        inner.style.height = state.layout.height + 'px';

        var svgNS = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('width', state.layout.width);
        svg.setAttribute('height', state.layout.height);
        svg.setAttribute('class', 'merkle-tree-svg');

        var level, j;
        for (level = 1; level < state.rows.length; level++) {
            for (j = 0; j < state.rows[level].length; j++) {
                var l = 2 * j, r = 2 * j + 1;
                var childIdxs = (r < state.rows[level - 1].length) ? [l, r] : [l];
                childIdxs.forEach(function (ci) {
                    var line = document.createElementNS(svgNS, 'line');
                    line.setAttribute('x1', state.layout.xs[level - 1][ci]);
                    line.setAttribute('y1', state.layout.ys[level - 1]);
                    line.setAttribute('x2', state.layout.xs[level][j]);
                    line.setAttribute('y2', state.layout.ys[level]);
                    line.setAttribute('class', 'merkle-edge');
                    line.dataset.level = level;
                    line.dataset.idx = j;
                    line.dataset.childIdx = ci;
                    svg.appendChild(line);
                });
            }
        }
        inner.appendChild(svg);

        var nodesLayer = el('div', 'merkle-nodes-layer');
        var lvl, i;
        for (lvl = 0; lvl < state.rows.length; lvl++) {
            for (i = 0; i < state.rows[lvl].length; i++) {
                var isRoot = lvl === state.rows.length - 1;
                var node = el('div', 'merkle-node' + (lvl === 0 ? ' leaf' : '') + (isRoot ? ' root' : ''));
                node.style.left = (state.layout.xs[lvl][i] - NODE_W / 2) + 'px';
                node.style.top = (state.layout.ys[lvl] - NODE_H / 2) + 'px';
                node.style.width = NODE_W + 'px';
                node.style.height = NODE_H + 'px';
                node.dataset.level = lvl;
                node.dataset.idx = i;
                var hashB64 = state.rowsB64[lvl][i];
                var label = lvl === 0 ? ('seg ' + state.segmentIds[i]) : (isRoot ? 'ROOT' : ('L' + lvl + '·' + i));
                node.title = label + '\n' + hashB64;
                node.innerHTML = '<span class="merkle-node-label">' + label + '</span><span class="merkle-node-hash">' + short(hashB64) + '</span>';
                if (lvl === 0) {
                    node.style.cursor = 'pointer';
                    (function (segId) {
                        node.addEventListener('click', function () {
                            var video = document.getElementById('video');
                            if (video) { video.currentTime = (segId - FIRST_SEGMENT) * SEGMENT_DURATION + 0.05; }
                        });
                    })(state.segmentIds[i]);
                }
                nodesLayer.appendChild(node);
            }
        }
        inner.appendChild(nodesLayer);
        container.appendChild(inner);
    }

    function renderFooter(footerId) {
        var footer = document.getElementById(footerId);
        if (!footer) { return; }
        var ok = state.root === state.manifestRoot;
        footer.className = 'merkle-tree-footer ' + (ok ? 'ok' : 'bad');
        footer.innerHTML = 'Recomputed root ' + (ok ? 'matches' : 'does NOT match') + ' manifest root: ' +
            '<span class="mono">' + short(state.root) + '</span>' + (ok ? ' ✓' : ' ✗');
    }

    function clearHighlight(container) {
        Array.prototype.forEach.call(container.querySelectorAll('.merkle-node'), function (n) {
            n.classList.remove('path', 'sibling', 'current', 'status-valid', 'status-invalid');
        });
        Array.prototype.forEach.call(container.querySelectorAll('.merkle-edge'), function (e) {
            e.classList.remove('active');
        });
    }

    function highlight(containerId, stepsId, segmentId, status) {
        var container = document.getElementById(containerId);
        var stepsEl = document.getElementById(stepsId);
        if (!container || !state.rows) { return; }
        clearHighlight(container);

        if (segmentId == null) {
            if (stepsEl) { stepsEl.innerHTML = '<p class="hint">Play or click a segment leaf to see its proof path computed live.</p>'; }
            return;
        }
        var location = state.segmentIds.indexOf(segmentId);
        if (location < 0) { return; }

        var steps = pathForLocation(state.rows, location);
        var statusClass = status === 'valid' ? 'status-valid' : status === 'invalid' ? 'status-invalid' : '';
        var stepsHtml = '<p class="hint">Segment ' + segmentId + ' — leaf #' + location + '</p><ol class="merkle-steps-list">';

        steps.forEach(function (step, i) {
            var curNode = container.querySelector('.merkle-node[data-level="' + step.level + '"][data-idx="' + step.idx + '"]');
            if (curNode) {
                addClass(curNode, 'path', statusClass);
                if (i === 0) { addClass(curNode, 'current'); }
            }
            var curLabel = step.level === 0 ? ('seg ' + segmentId) : ('L' + step.level + '·' + step.idx);
            var parentIdx = Math.floor(step.idx / 2);
            if (step.hasSibling) {
                var sibNode = container.querySelector('.merkle-node[data-level="' + step.level + '"][data-idx="' + step.siblingIdx + '"]');
                if (sibNode) { addClass(sibNode, 'sibling'); }
                var sibLabel = step.level === 0 ? ('seg ' + state.segmentIds[step.siblingIdx]) : ('L' + step.level + '·' + step.siblingIdx);
                var left = step.side === 'left' ? curLabel : sibLabel;
                var right = step.side === 'left' ? sibLabel : curLabel;
                stepsHtml += '<li>H(' + left + ' ‖ ' + right + ') → L' + (step.level + 1) + '·' + parentIdx + '</li>';
            } else {
                stepsHtml += '<li>' + curLabel + ' has no sibling at this level — promoted unchanged to L' + (step.level + 1) + '·' + parentIdx + '</li>';
            }
            var edge = container.querySelector('.merkle-edge[data-level="' + (step.level + 1) + '"][data-idx="' + parentIdx + '"][data-child-idx="' + step.idx + '"]');
            if (edge) { edge.classList.add('active'); }
        });
        stepsHtml += '</ol>';

        var rootNode = container.querySelector('.merkle-node.root');
        if (rootNode) { addClass(rootNode, 'path', statusClass); }
        if (stepsEl) { stepsEl.innerHTML = stepsHtml; }

        var curLeaf = container.querySelector('.merkle-node.leaf.current');
        if (curLeaf) {
            var target = curLeaf.offsetLeft - container.clientWidth / 2 + curLeaf.offsetWidth / 2;
            container.scrollTo({ left: Math.max(0, target), behavior: 'smooth' });
        }
    }

    global.C2PAMerkleViz = {
        init: function (containerId, footerId, stepsId) {
            return buildTree().then(function () {
                render(containerId);
                renderFooter(footerId);
                highlight(containerId, stepsId, null);
            });
        },
        highlight: highlight
    };
})(window);
