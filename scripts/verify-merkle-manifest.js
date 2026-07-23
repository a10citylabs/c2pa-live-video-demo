#!/usr/bin/env node
/**
 * Self-test for the Merkle-proof video segment manifest: for every segment
 * listed in video_merkle_manifest.json, recompute its leaf hash from the
 * raw segment file, walk it up through the segment's proof, and confirm
 * the reconstructed root matches the manifest's stored root — exactly
 * what js/merkle.js does in the browser (see that file's verifySegment).
 *
 * Also runs one negative case: a single flipped byte in a segment must
 * change its leaf hash and therefore make the reconstructed root diverge
 * from the manifest, proving the proof isn't a rubber stamp.
 *
 * Usage: node scripts/verify-merkle-manifest.js
 */
'use strict';

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var core = require('../js/merkle-core.js');

var SAMPLE_DIR = path.join(__dirname, '..', 'samples', 'live-streaming', 'Video', 'Per-segment-C2PA-Manifest-Box-method');
var MANIFEST_FILE = path.join(SAMPLE_DIR, 'video_merkle_manifest.json');

function sha256(bytes) {
    return Promise.resolve(new Uint8Array(crypto.createHash('sha256').update(bytes).digest()));
}

function fromBase64(s) {
    return new Uint8Array(Buffer.from(s, 'base64'));
}

function toBase64(u8) {
    return Buffer.from(u8).toString('base64');
}

function verifySegmentBytes(manifest, seg, fileBytes) {
    var merkleMap = manifest.bmffHashAssertion.merkle[0];
    var expectedRoot = merkleMap.hashes[0];
    var proof = seg.bmffMerkleMap.hashes.map(fromBase64);

    return sha256(core.hashableBytes(fileBytes)).then(function (leafHash) {
        return core.reconstructRoot(leafHash, proof, seg.location, merkleMap.count, sha256).then(function (computedRoot) {
            return {
                segmentId: seg.segmentId,
                leafMatches: toBase64(leafHash) === seg.leafHash,
                rootMatches: toBase64(computedRoot) === expectedRoot,
                computedRoot: toBase64(computedRoot),
                expectedRoot: expectedRoot
            };
        });
    });
}

async function main() {
    var manifest = JSON.parse(fs.readFileSync(MANIFEST_FILE, 'utf8'));
    var failures = 0;

    console.log('Verifying ' + manifest.segments.length + ' segments against ' + path.relative(process.cwd(), MANIFEST_FILE));
    console.log('Root row (manifest):', manifest.bmffHashAssertion.merkle[0].hashes[0]);
    console.log('');

    for (var i = 0; i < manifest.segments.length; i++) {
        var seg = manifest.segments[i];
        var fileBytes = new Uint8Array(fs.readFileSync(path.join(SAMPLE_DIR, seg.file)));
        var result = await verifySegmentBytes(manifest, seg, fileBytes);
        var ok = result.leafMatches && result.rootMatches;
        if (!ok) {
            failures++;
        }
        console.log((ok ? 'PASS' : 'FAIL') + '  segment ' + seg.segmentId + '  location=' + seg.location +
            '  leaf=' + (result.leafMatches ? 'ok' : 'MISMATCH') +
            '  root=' + (result.rootMatches ? 'ok' : 'MISMATCH'));
    }

    console.log('');
    console.log(failures === 0 ? 'All segments verified against the Merkle root.' : (failures + ' segment(s) FAILED.'));

    // Negative test: tamper one byte of one segment's mdat payload in
    // memory only (the file on disk is never touched) and confirm the
    // reconstructed root now diverges from the manifest.
    var tamperSeg = manifest.segments[0];
    var tamperedBytes = new Uint8Array(fs.readFileSync(path.join(SAMPLE_DIR, tamperSeg.file)));
    var boxes = core.walkTopBoxes(tamperedBytes);
    var mdat = boxes.filter(function (b) { return b.type === 'mdat'; })[0];
    if (!mdat) {
        throw new Error('no mdat box found in ' + tamperSeg.file);
    }
    var flipAt = mdat.pos + mdat.hdr + Math.floor((mdat.size - mdat.hdr) / 2);
    tamperedBytes[flipAt] ^= 0xff;
    var tamperedResult = await verifySegmentBytes(manifest, tamperSeg, tamperedBytes);

    console.log('');
    console.log('Tamper check (segment ' + tamperSeg.segmentId + ', 1 byte flipped in mdat):');
    console.log('  ' + (tamperedResult.rootMatches ? 'FAIL — tampering was not detected!' : 'PASS — reconstructed root no longer matches, as expected'));

    if (failures > 0 || tamperedResult.rootMatches) {
        process.exit(1);
    }
}

main().catch(function (err) {
    console.error(err);
    process.exit(1);
});
