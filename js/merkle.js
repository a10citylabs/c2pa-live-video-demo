/**
 * Browser-side Merkle-proof verification for live video segments, per
 * C2PA Technical Specification 2.4, Section 9.2.3 and Appendix A.5.4 (see
 * js/merkle-core.js for the shared tree/proof algorithm and
 * samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/
 * Merkle-Proof-Video-Segment-Validation.md for the full method).
 *
 * Given the manifest produced by scripts/build-merkle-manifest.js and one
 * segment's raw bytes:
 *   1. Look up the segment's `bmffMerkleMap` proof by segmentId.
 *   2. Recompute the segment's leaf hash (whole file minus its C2PA
 *      'uuid' box, matching how the manifest's leaves were built).
 *   3. Walk the leaf hash up through the proof's sibling hashes
 *      (`location`/`count` determine, at each level, whether a sibling
 *      hash is consumed and which side it's on).
 *   4. Compare the reconstructed root to the root stored in the manifest.
 */
(function (global) {
    'use strict';

    var core = global.C2PAMerkleCore;

    function sha256(bytes) {
        return crypto.subtle.digest('SHA-256', bytes).then(function (d) {
            return new Uint8Array(d);
        });
    }

    function fromBase64(s) {
        var bin = atob(s);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) {
            out[i] = bin.charCodeAt(i);
        }
        return out;
    }

    function toBase64(u8) {
        var s = '';
        for (var i = 0; i < u8.length; i++) {
            s += String.fromCharCode(u8[i]);
        }
        return btoa(s);
    }

    function loadManifest(url) {
        return fetch(url).then(function (r) { return r.json(); });
    }

    /**
     * Verifies one segment's raw bytes against the Merkle manifest.
     * Resolves to { status: 'valid'|'invalid'|'no-proof', segmentId,
     *   location, leafHash, computedRoot, expectedRoot, proofLength,
     *   durationMs }.
     */
    function verifySegment(manifest, segmentId, arrayBufferOrU8) {
        var started = performance.now();
        var seg = manifest.segments.filter(function (s) { return s.segmentId === segmentId; })[0];
        if (!seg) {
            return Promise.resolve({ status: 'no-proof', segmentId: segmentId });
        }

        var u8 = arrayBufferOrU8 instanceof Uint8Array ? arrayBufferOrU8 : new Uint8Array(arrayBufferOrU8);
        var merkleMap = manifest.bmffHashAssertion.merkle[0];
        var expectedRoot = merkleMap.hashes[0];
        var proof = seg.bmffMerkleMap.hashes.map(fromBase64);

        return sha256(core.hashableBytes(u8)).then(function (leafHash) {
            return core.reconstructRoot(leafHash, proof, seg.location, merkleMap.count, sha256).then(function (computedRoot) {
                var computedRootB64 = toBase64(computedRoot);
                return {
                    status: computedRootB64 === expectedRoot ? 'valid' : 'invalid',
                    segmentId: segmentId,
                    location: seg.location,
                    leafHash: toBase64(leafHash),
                    computedRoot: computedRootB64,
                    expectedRoot: expectedRoot,
                    proofLength: proof.length,
                    durationMs: performance.now() - started
                };
            });
        }).catch(function (err) {
            return {
                status: 'invalid',
                segmentId: segmentId,
                error: String(err && err.message || err),
                durationMs: performance.now() - started
            };
        });
    }

    global.C2PAMerkle = {
        loadManifest: loadManifest,
        verifySegment: verifySegment
    };
})(window);
