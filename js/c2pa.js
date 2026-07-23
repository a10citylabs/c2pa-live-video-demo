/**
 * Minimal C2PA live-segment verification.
 *
 * Implements the per-segment "C2PA Manifest Box" method documented in
 * samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/C2PA-Live-Segment-Validation.md:
 *
 *  1. Extract the C2PA manifest store (JUMBF) embedded in the segment's `uuid` box.
 *  2. Read the c2pa.IVHASH assertion parameters
 *     (segmentId, anchorSegmentIndex, streamIdHash, certHash, continuityToken).
 *  3. Concatenate the segment's moof + mdat boxes.
 *  4. Derive the per-segment IV from the anchor segment
 *     (sha256(streamIdHash + anchorNumber)[0..16], incremented per segment).
 *  5. AES-128-CBC encrypt moof+mdat (key = first 16 chars of certHash); the last
 *     ciphertext block, base64 encoded, is the expected continuity token.
 *  6. Compare against the continuityToken carried in the manifest.
 */
(function (global) {
    'use strict';

    var C2PA_UUID = [0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81];

    /* ------------------------------------------------------------------ *
     *  ISO BMFF box parsing
     * ------------------------------------------------------------------ */

    function walkBoxes(u8, start, end, cb) {
        var pos = start;
        while (pos + 8 <= end) {
            var dv = new DataView(u8.buffer, u8.byteOffset + pos, Math.min(16, end - pos));
            var size = dv.getUint32(0);
            var type = String.fromCharCode(u8[pos + 4], u8[pos + 5], u8[pos + 6], u8[pos + 7]);
            var hdr = 8;
            if (size === 1) {
                size = Number(dv.getBigUint64(8));
                hdr = 16;
            }
            if (size <= 0 || pos + size > end) {
                break;
            }
            cb({ type: type, pos: pos, size: size, hdr: hdr });
            pos += size;
        }
    }

    function isC2paUuid(u8, box) {
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

    /* ------------------------------------------------------------------ *
     *  JUMBF parsing
     * ------------------------------------------------------------------ */

    // Collects { label, contentType, payload } for every jumb superbox.
    function parseJumbf(u8, start, end, out, path) {
        walkBoxes(u8, start, end, function (b) {
            if (b.type !== 'jumb') {
                return;
            }
            var children = [];
            walkBoxes(u8, b.pos + b.hdr, b.pos + b.size, function (c) { children.push(c); });
            var jumd = children[0];
            if (!jumd || jumd.type !== 'jumd') {
                return;
            }
            var p = jumd.pos + jumd.hdr + 16;
            var toggles = u8[p];
            p += 1;
            var label = '';
            if (toggles & 0x02) {
                while (u8[p] !== 0 && p < jumd.pos + jumd.size) {
                    label += String.fromCharCode(u8[p++]);
                }
            }
            var full = path ? path + '/' + label : label;
            for (var i = 1; i < children.length; i++) {
                var c = children[i];
                if (c.type !== 'jumb') {
                    out.push({
                        label: full,
                        contentType: c.type,
                        payload: u8.subarray(c.pos + c.hdr, c.pos + c.size)
                    });
                }
            }
            parseJumbf(u8, b.pos + b.hdr, b.pos + b.size, out, full);
        });
    }

    /* ------------------------------------------------------------------ *
     *  Minimal CBOR decoder (subset used by C2PA manifests)
     * ------------------------------------------------------------------ */

    function cborDecode(u8) {
        var pos = 0;
        var td = new TextDecoder();

        function read() {
            var ib = u8[pos++];
            var mt = ib >> 5;
            var ai = ib & 0x1f;
            var val;
            if (ai < 24) {
                val = ai;
            } else if (ai === 24) {
                val = u8[pos++];
            } else if (ai === 25) {
                val = (u8[pos] << 8) | u8[pos + 1];
                pos += 2;
            } else if (ai === 26) {
                val = u8[pos] * 0x1000000 + ((u8[pos + 1] << 16) | (u8[pos + 2] << 8) | u8[pos + 3]);
                pos += 4;
            } else if (ai === 27) {
                val = Number(new DataView(u8.buffer, u8.byteOffset + pos, 8).getBigUint64(0));
                pos += 8;
            } else if (ai === 31) {
                val = Infinity;
            } else {
                throw new Error('cbor: unsupported additional info ' + ai);
            }
            var out, i, k;
            switch (mt) {
                case 0: return val;
                case 1: return -1 - val;
                case 2:
                    out = u8.subarray(pos, pos + val);
                    pos += val;
                    return out;
                case 3:
                    out = td.decode(u8.subarray(pos, pos + val));
                    pos += val;
                    return out;
                case 4:
                    out = [];
                    for (i = 0; val === Infinity ? u8[pos] !== 0xff : i < val; i++) {
                        out.push(read());
                    }
                    if (val === Infinity) pos++;
                    return out;
                case 5:
                    out = {};
                    for (i = 0; val === Infinity ? u8[pos] !== 0xff : i < val; i++) {
                        k = read();
                        out[k] = read();
                    }
                    if (val === Infinity) pos++;
                    return out;
                case 6: return { tag: val, value: read() };
                case 7:
                    if (ai === 20) return false;
                    if (ai === 21) return true;
                    if (ai === 22) return null;
                    if (ai === 23) return undefined;
                    if (ai === 26) { out = new DataView(u8.buffer, u8.byteOffset + pos, 4).getFloat32(0); pos += 4; return out; }
                    if (ai === 27) { out = new DataView(u8.buffer, u8.byteOffset + pos, 8).getFloat64(0); pos += 8; return out; }
                    return null;
            }
            throw new Error('cbor: bad major type');
        }

        return read();
    }

    /* ------------------------------------------------------------------ *
     *  Tiny X.509/DER helpers (signer display info only)
     * ------------------------------------------------------------------ */

    // Extracts CN/O attribute strings from a DER certificate, in order of
    // appearance: issuer attributes come before subject attributes.
    function certNames(der) {
        var names = [];
        for (var i = 0; i + 5 < der.length; i++) {
            // OID 2.5.4.x => 06 03 55 04 xx, followed by a string type
            if (der[i] === 0x06 && der[i + 1] === 0x03 && der[i + 2] === 0x55 && der[i + 3] === 0x04) {
                var attr = der[i + 4];
                var strType = der[i + 5];
                if (strType === 0x0c || strType === 0x13) { // utf8String | printableString
                    var len = der[i + 6];
                    var val = '';
                    for (var j = 0; j < len; j++) {
                        val += String.fromCharCode(der[i + 7 + j]);
                    }
                    names.push({ attr: attr, value: val });
                }
            }
        }
        return names;
    }

    function pickName(names, attrs) {
        var parts = [];
        attrs.forEach(function (a) {
            names.forEach(function (n) {
                if (n.attr === a && parts.indexOf(n.value) === -1) {
                    parts.push(n.value);
                }
            });
        });
        return parts.join(', ');
    }

    /* ------------------------------------------------------------------ *
     *  Manifest extraction
     * ------------------------------------------------------------------ */

    function extractManifest(u8) {
        var jumbfRaw = null;
        var moofMdatParts = [];
        var total = 0;

        walkBoxes(u8, 0, u8.length, function (b) {
            if (isC2paUuid(u8, b)) {
                // payload: version+flags (4) | purpose cstring | merkle offset (8) | JUMBF
                var p = b.pos + b.hdr + 16 + 4;
                var end = b.pos + b.size;
                while (u8[p] !== 0 && p < end) p++;
                p += 1 + 8;
                jumbfRaw = u8.subarray(p, end);
            } else if (b.type === 'moof' || b.type === 'mdat') {
                moofMdatParts.push(u8.subarray(b.pos, b.pos + b.size));
                total += b.size;
            }
        });

        if (!jumbfRaw) {
            return null;
        }

        var entries = [];
        parseJumbf(jumbfRaw, 0, jumbfRaw.length, entries, '');

        var manifest = {
            ivhash: null,
            creativeWork: null,
            claim: null,
            signer: null,
            assertionLabels: []
        };

        entries.forEach(function (e) {
            var short = e.label.split('/').pop();
            if (e.label.indexOf('c2pa.assertions/') !== -1) {
                if (manifest.assertionLabels.indexOf(short) === -1) {
                    manifest.assertionLabels.push(short);
                }
            }
            try {
                if (short === 'c2pa.livevideo.segment' && e.contentType === 'cbor') {
                    var seg = cborDecode(e.payload);
                    (seg.actions || []).forEach(function (a) {
                        if (a.action === 'c2pa.IVHASH') {
                            manifest.ivhash = a.parameters;
                        }
                    });
                } else if (short === 'stds.schema-org.CreativeWork' && e.contentType === 'json') {
                    manifest.creativeWork = JSON.parse(new TextDecoder().decode(e.payload));
                } else if (short === 'c2pa.claim' && e.contentType === 'cbor') {
                    manifest.claim = cborDecode(e.payload);
                } else if (short === 'c2pa.signature' && e.contentType === 'cbor') {
                    manifest.signer = parseSigner(cborDecode(e.payload));
                }
            } catch (err) {
                /* tolerate individual assertion parse issues */
            }
        });

        var moofMdat = new Uint8Array(total);
        var off = 0;
        moofMdatParts.forEach(function (part) {
            moofMdat.set(part, off);
            off += part.length;
        });

        return { manifest: manifest, moofMdat: moofMdat };
    }

    // COSE_Sign1: [protected(bstr of cbor map), unprotected, payload, signature].
    // x5chain (header label 33) carries the DER certificate chain.
    function parseSigner(cose) {
        try {
            var arr = cose && cose.tag === 18 ? cose.value : cose;
            if (!Array.isArray(arr)) {
                return null;
            }
            var chain = null;
            var prot = arr[0] && arr[0].length ? cborDecode(arr[0]) : {};
            if (prot[33]) chain = prot[33];
            if (!chain && arr[1] && arr[1][33]) chain = arr[1][33];
            if (!chain) {
                return null;
            }
            var der = Array.isArray(chain) ? chain[0] : chain;
            var names = certNames(der);
            // Issuer attributes appear first in the DER; the subject set repeats
            // CN/O later, so read from the tail for the subject.
            var cns = names.filter(function (n) { return n.attr === 0x03; });
            var os = names.filter(function (n) { return n.attr === 0x0a; });
            return {
                issuedBy: cns.length ? cns[0].value : pickName(names, [0x0a]),
                subject: cns.length > 1 ? cns[cns.length - 1].value : null,
                organization: os.length > 1 ? os[os.length - 1].value : (os.length === 1 ? os[0].value : null),
                alg: prot[1]
            };
        } catch (e) {
            return null;
        }
    }

    /* ------------------------------------------------------------------ *
     *  Continuity token computation (WebCrypto)
     * ------------------------------------------------------------------ */

    function sha256(bytes) {
        return crypto.subtle.digest('SHA-256', bytes).then(function (d) {
            return new Uint8Array(d);
        });
    }

    function incrementIv(iv) {
        var out = new Uint8Array(iv);
        for (var i = out.length - 1; i >= 0; i--) {
            out[i]++;
            if (out[i] !== 0) {
                break;
            }
        }
        return out;
    }

    function deriveIv(segmentId, anchorSegmentIndex, streamIdHash) {
        var anchorNumber = Math.floor(segmentId / anchorSegmentIndex) * anchorSegmentIndex;
        var seed = new TextEncoder().encode(streamIdHash + anchorNumber.toString());
        return sha256(seed).then(function (digest) {
            var iv = digest.slice(0, 16);
            for (var i = 0; i < segmentId - anchorNumber; i++) {
                iv = incrementIv(iv);
            }
            return iv;
        });
    }

    function toBase64(u8) {
        var s = '';
        for (var i = 0; i < u8.length; i++) {
            s += String.fromCharCode(u8[i]);
        }
        return btoa(s);
    }

    function toHex(u8) {
        return Array.prototype.map.call(u8, function (b) {
            return ('0' + b.toString(16)).slice(-2);
        }).join('');
    }

    // AES-128-CBC over moof+mdat; the final ciphertext block (before PKCS#7
    // padding removal — WebCrypto encrypt output includes it) is the token.
    function computeContinuityToken(moofMdat, certHash, iv) {
        var keyBytes = new TextEncoder().encode(certHash.substring(0, 16));
        return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt'])
            .then(function (key) {
                return crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, key, moofMdat);
            })
            .then(function (cipher) {
                var u8 = new Uint8Array(cipher);
                return toBase64(u8.slice(-16));
            });
    }

    /**
     * Verifies one media segment. Resolves to a result object:
     * { status: 'valid'|'invalid'|'no-manifest', manifest, segmentId, expected,
     *   computed, iv, bytesHashed, durationMs }
     */
    function verifySegment(arrayBufferOrU8) {
        var u8 = arrayBufferOrU8 instanceof Uint8Array ? arrayBufferOrU8 : new Uint8Array(arrayBufferOrU8);
        var started = performance.now();
        var extracted;
        try {
            extracted = extractManifest(u8);
        } catch (e) {
            extracted = null;
        }
        if (!extracted || !extracted.manifest.ivhash) {
            return Promise.resolve({
                status: 'no-manifest',
                manifest: extracted ? extracted.manifest : null
            });
        }
        var p = extracted.manifest.ivhash;
        return deriveIv(p.segmentId, p.anchorSegmentIndex, p.streamIdHash).then(function (iv) {
            return computeContinuityToken(extracted.moofMdat, p.certHash, iv).then(function (computed) {
                return {
                    status: computed === p.continuityToken ? 'valid' : 'invalid',
                    manifest: extracted.manifest,
                    segmentId: p.segmentId,
                    expected: p.continuityToken,
                    computed: computed,
                    iv: toHex(iv),
                    bytesHashed: extracted.moofMdat.length,
                    durationMs: performance.now() - started
                };
            });
        });
    }

    global.C2PA = {
        verifySegment: verifySegment,
        extractManifest: extractManifest
    };
})(window);
