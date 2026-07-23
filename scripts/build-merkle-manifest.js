#!/usr/bin/env node
/**
 * Builds a C2PA-style fragmented-BMFF Merkle tree manifest for the sample
 * video segments (see js/merkle-core.js for the algorithm, and
 * samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/
 * Merkle-Proof-Video-Segment-Validation.md for the spec references).
 *
 * For every video segment (leaf, in playback order):
 *   leafHash = sha256(whole segment file minus its C2PA 'uuid' box)
 * These 20 leaves are combined into a binary Merkle tree (C2PA 2.4
 * Section 9.2.3 / Appendix A.5.4). The manifest stores only the root row
 * (`merkle[].hashes`) plus, per segment, the `bmff-merkle-map` proof
 * (`location` + sibling `hashes`) that a validator needs to recompute the
 * root from that one segment.
 *
 * Usage: node scripts/build-merkle-manifest.js
 */
'use strict';

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var core = require('../js/merkle-core.js');

var SAMPLE_DIR = path.join(__dirname, '..', 'samples', 'live-streaming', 'Video', 'Per-segment-C2PA-Manifest-Box-method');
var M4S_DIR = path.join(SAMPLE_DIR, 'm4s');
var INIT_FILE = path.join(M4S_DIR, 'init.mp4');
var OUT_FILE = path.join(SAMPLE_DIR, 'video_merkle_manifest.json');
var TRACK_ID = 1; // video track_id, read from the init segment's 'tkhd' (and each fragment's 'tfhd')
var UNIQUE_ID = 1; // single Merkle tree (one video track) in this sample

function sha256(bytes) {
    return Promise.resolve(new Uint8Array(crypto.createHash('sha256').update(bytes).digest()));
}

function toBase64(u8) {
    return Buffer.from(u8).toString('base64');
}

function listSegments() {
    return fs.readdirSync(M4S_DIR)
        .map(function (name) {
            var m = /^seg_(\d+)\.m4s$/.exec(name);
            return m ? { name: name, segmentId: parseInt(m[1], 10) } : null;
        })
        .filter(Boolean)
        .sort(function (a, b) { return a.segmentId - b.segmentId; });
}

async function main() {
    var segments = listSegments();
    if (segments.length === 0) {
        throw new Error('no seg_*.m4s files found in ' + M4S_DIR);
    }

    var initBytes = new Uint8Array(fs.readFileSync(INIT_FILE));
    var initHash = await sha256(core.hashableBytes(initBytes));

    var leafHashes = [];
    for (var i = 0; i < segments.length; i++) {
        var bytes = new Uint8Array(fs.readFileSync(path.join(M4S_DIR, segments[i].name)));
        leafHashes.push(await sha256(core.hashableBytes(bytes)));
    }

    var rows = await core.buildMerkleRows(leafHashes, sha256);
    var root = rows[rows.length - 1][0];

    var manifest = {
        specReference: 'C2PA Technical Specification 2.4, Section 9.2.3 (Hashing a BMFF-formatted asset) and Appendix A.5.4 (Auxiliary c2pa Boxes for Large and Fragmented Files)',
        generatedAt: new Date().toISOString(),
        asset: {
            initSegment: 'm4s/init.mp4',
            track: 'video',
            trackId: TRACK_ID,
            segmentCount: segments.length
        },
        bmffHashAssertion: {
            label: 'c2pa.hash.bmff.v3',
            alg: 'sha256',
            merkle: [
                {
                    uniqueId: UNIQUE_ID,
                    localId: TRACK_ID,
                    count: leafHashes.length,
                    alg: 'sha256',
                    initHash: toBase64(initHash),
                    hashes: [toBase64(root)]
                }
            ]
        },
        segments: segments.map(function (seg, i) {
            var proof = core.buildProof(rows, i);
            return {
                segmentId: seg.segmentId,
                file: 'm4s/' + seg.name,
                location: i,
                leafHash: toBase64(leafHashes[i]),
                bmffMerkleMap: {
                    uniqueId: UNIQUE_ID,
                    localId: TRACK_ID,
                    location: i,
                    hashes: proof.map(toBase64)
                }
            };
        })
    };

    fs.writeFileSync(OUT_FILE, JSON.stringify(manifest, null, 2) + '\n');
    console.log('wrote ' + OUT_FILE);
    console.log('leaves: ' + leafHashes.length + ', tree depth: ' + (rows.length - 1) + ', root: ' + toBase64(root));
}

main().catch(function (err) {
    console.error(err);
    process.exit(1);
});
