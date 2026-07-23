/**
 * Isomorphic Merkle tree / proof math for the C2PA fragmented-BMFF Merkle
 * tree scheme (C2PA Technical Specification 2.4, Section 9.2.3 "Hashing a
 * BMFF-formatted asset" and Appendix A.5.4 "Auxiliary 'c2pa' Boxes for
 * Large and Fragmented Files").
 *
 * Per the spec:
 *  - Each fragment (fMP4 segment) is one leaf of a per-track Merkle tree.
 *    Its leaf hash covers "all data in its containing single fragment file
 *    except data excluded by the exclusion list" (A.5.4.1.2), i.e. the
 *    whole file minus the entire C2PA 'uuid' box (and 'ftyp'/'mfra' if
 *    present — mandatory exclusions, Appendix A.5.6).
 *  - The manifest stores one row of the tree (`merkle-map.hashes`, here the
 *    root row) plus a `count` of leaf nodes and, for split-file fragmented
 *    assets, an `initHash` over the initialization segment.
 *  - Each fragment is paired with a `bmff-merkle-map` proof: `location`
 *    (zero-based leaf index) plus the ordered sibling `hashes` needed to
 *    walk from the leaf up to the row stored in the manifest. "Null"
 *    siblings (an unpaired node promoted to the row above unchanged) are
 *    never included in that array — this module derives their positions
 *    from `count`/`location` alone, with no separate flag needed.
 *
 * No crypto is imported here; every function takes a `sha256` function
 * (bytes -> Promise<Uint8Array>) so the same tree/proof logic runs under
 * WebCrypto in the browser and node:crypto in build/verification scripts.
 */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.C2PAMerkleCore = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var C2PA_UUID = [0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81];

    /* ------------------------------------------------------------------ *
     *  ISO-BMFF top-level box walking + C2PA-mandatory exclusions
     * ------------------------------------------------------------------ */

    function walkTopBoxes(u8) {
        var pos = 0;
        var n = u8.length;
        var out = [];
        while (pos + 8 <= n) {
            var dv = new DataView(u8.buffer, u8.byteOffset + pos, Math.min(16, n - pos));
            var size = dv.getUint32(0);
            var type = String.fromCharCode(u8[pos + 4], u8[pos + 5], u8[pos + 6], u8[pos + 7]);
            var hdr = 8;
            if (size === 1) {
                size = Number(dv.getBigUint64(8));
                hdr = 16;
            }
            if (size <= 0 || pos + size > n) {
                break;
            }
            out.push({ type: type, pos: pos, size: size, hdr: hdr });
            pos += size;
        }
        return out;
    }

    function isC2paUuidBox(u8, box) {
        if (box.type !== 'uuid') {
            return false;
        }
        for (var i = 0; i < 16; i++) {
            if (u8[box.pos + box.hdr + i] !== C2PA_UUID[i]) {
                return false;
            }
        }
        return true;
    }

    // Bytes contributed to a Merkle leaf hash: the whole file, in box
    // order, minus the entire 'ftyp'/'mfra' boxes and the entire C2PA
    // 'uuid' box (Appendix A.5.6, "Exclusion List Requirements").
    function hashableBytes(u8) {
        var boxes = walkTopBoxes(u8);
        var parts = [];
        var total = 0;
        boxes.forEach(function (b) {
            if (b.type === 'ftyp' || b.type === 'mfra') {
                return;
            }
            if (isC2paUuidBox(u8, b)) {
                return;
            }
            var part = u8.subarray(b.pos, b.pos + b.size);
            parts.push(part);
            total += part.length;
        });
        var out = new Uint8Array(total);
        var off = 0;
        parts.forEach(function (p) {
            out.set(p, off);
            off += p.length;
        });
        return out;
    }

    /* ------------------------------------------------------------------ *
     *  Merkle tree construction / proof extraction / proof verification
     * ------------------------------------------------------------------ */

    function concatBytes(a, b) {
        var out = new Uint8Array(a.length + b.length);
        out.set(a, 0);
        out.set(b, a.length);
        return out;
    }

    // rows[0] = leaves ... rows[rows.length - 1] = [root]. An odd node out
    // in a row has no sibling and is promoted to the row above unchanged
    // (the spec's "null node", excluded from both `count` and `hashes`).
    function buildMerkleRows(leafHashes, sha256) {
        var rows = [leafHashes.slice()];
        var row = leafHashes;
        function nextRow() {
            if (row.length <= 1) {
                return Promise.resolve(rows);
            }
            var pairs = [];
            for (var i = 0; i < row.length; i += 2) {
                pairs.push(i);
            }
            return pairs.reduce(function (p, i) {
                return p.then(function (acc) {
                    if (i + 1 < row.length) {
                        return sha256(concatBytes(row[i], row[i + 1])).then(function (h) {
                            acc.push(h);
                            return acc;
                        });
                    }
                    acc.push(row[i]);
                    return acc;
                });
            }, Promise.resolve([])).then(function (next) {
                rows.push(next);
                row = next;
                return nextRow();
            });
        }
        return nextRow();
    }

    function hasSiblingAt(idx, levelSize) {
        var isLast = idx === levelSize - 1;
        return !(isLast && (levelSize % 2 === 1));
    }

    // Ordered sibling hashes from the leaf at `location` up to (but not
    // including) the row at `rows[rows.length - 1]` (the root row, or
    // whichever row is being treated as the manifest-resident row).
    function buildProof(rows, location, uptoRowIndex) {
        var proof = [];
        var idx = location;
        var last = typeof uptoRowIndex === 'number' ? uptoRowIndex : rows.length - 1;
        for (var level = 0; level < last; level++) {
            var levelSize = rows[level].length;
            if (hasSiblingAt(idx, levelSize)) {
                var siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
                proof.push(rows[level][siblingIdx]);
            }
            idx = Math.floor(idx / 2);
        }
        return proof;
    }

    // Walks a leaf hash up through `proof` (siblings, leaf-most first)
    // using only `location` and `count` to know, at each level, whether a
    // sibling existed (see `hasSiblingAt`) and which side it was on.
    // Returns the reconstructed hash at the top of the tree described by
    // `count`/`proof` (compare against the manifest's stored root/row).
    function reconstructRoot(leafHash, proof, location, count, sha256) {
        var idx = location;
        var levelSize = count;
        var hash = leafHash;
        var p = 0;

        function step() {
            if (levelSize <= 1) {
                if (p !== proof.length) {
                    return Promise.reject(new Error('merkle proof has ' + (proof.length - p) + ' unused hash(es)'));
                }
                return Promise.resolve(hash);
            }
            var proceed;
            if (hasSiblingAt(idx, levelSize)) {
                if (p >= proof.length) {
                    return Promise.reject(new Error('merkle proof is missing a hash for this segment'));
                }
                var sibling = proof[p++];
                proceed = idx % 2 === 0
                    ? sha256(concatBytes(hash, sibling))
                    : sha256(concatBytes(sibling, hash));
            } else {
                proceed = Promise.resolve(hash);
            }
            return proceed.then(function (h) {
                hash = h;
                idx = Math.floor(idx / 2);
                levelSize = Math.ceil(levelSize / 2);
                return step();
            });
        }

        return step();
    }

    return {
        C2PA_UUID: C2PA_UUID,
        walkTopBoxes: walkTopBoxes,
        isC2paUuidBox: isC2paUuidBox,
        hashableBytes: hashableBytes,
        concatBytes: concatBytes,
        buildMerkleRows: buildMerkleRows,
        hasSiblingAt: hasSiblingAt,
        buildProof: buildProof,
        reconstructRoot: reconstructRoot
    };
});
