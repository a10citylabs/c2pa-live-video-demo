# C2PA Merkle-Proof Video Segment Validation

This is a second, independent verification path for the same 20 video
segments, built on the actual Merkle tree mechanism the C2PA spec defines
for fragmented BMFF assets — as opposed to `C2PA-Live-Segment-Validation.md`'s
custom IVHASH/continuity-token scheme.

Reference: [C2PA Technical Specification 2.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html),
Section 9.2.3 "Hashing a BMFF-formatted asset" and Appendix A.5.4
"Auxiliary 'c2pa' Boxes for Large and Fragmented Files".

## How the spec's Merkle tree works

For a fragmented MP4 asset split across multiple files (our case: 20
independent `.m4s` segments plus `init.mp4`), the spec defines one Merkle
tree per track:

- **Leaf hash** (Appendix A.5.4.1.2): for each fragment file, the hash
  covers "all data in its containing single fragment file except data
  excluded by the exclusion list". The mandatory exclusions (Appendix
  A.5.6) are the entire `ftyp` box, the entire `mfra` box, and the entire
  C2PA `uuid` box. Our segments are `styp` + `uuid` (C2PA) + `sidx` +
  `moof` + `mdat`, so the leaf hash covers everything except the `uuid`
  box: `styp + sidx + moof + mdat`.
- **initHash** (`merkle-map.initHash`): required whenever the fragments are
  split across multiple files — "the hash of the entire initialization
  segment file ... excluding boxes listed in the exclusions array", i.e.
  `init.mp4` minus its `ftyp` box.
- **Tree construction**: leaves are paired left-to-right and hashed
  (`sha256(left || right)`) to build each row up to a single root. An
  unpaired trailing node (odd count at that level) is promoted to the row
  above unchanged — the spec's "null node", which is why `count` (leaf
  nodes) and `hashes` (a stored row) never include it explicitly.
- **What the manifest stores** (`bmff-hash-map.merkle[]`, one entry per
  track): `uniqueId`, `localId` (the track's `track_id`, read from
  `tkhd`/`tfhd`), `count`, `alg`, `initHash`, and `hashes` — one row of the
  tree. This sample stores the **root row** (a single hash), which
  minimizes manifest size at the cost of a full-depth proof per segment.
- **What each fragment needs** (`bmff-merkle-map`, normally carried in an
  auxiliary `uuid` C2PA box with `box_purpose` `merkle` immediately before
  each fragment's `moof`): `uniqueId`, `localId`, `location` (zero-based
  leaf index) and `hashes` — the ordered sibling hashes needed to walk from
  this leaf up to the row stored in the manifest. Null-node levels
  contribute no entry, so `location` and the manifest's `count` are what
  let a validator know, at each level, whether a hash should be consumed
  from the array and which side (left/right) it's on.

This demo keeps the proofs in a single JSON sidecar
(`video_merkle_manifest.json`) rather than mutating the `.m4s` files to add
real auxiliary `uuid` boxes, so the segment files on disk are untouched;
the JSON plays the role the auxiliary boxes + manifest would play together.

## Files

- [`video_merkle_manifest.json`](video_merkle_manifest.json) — generated
  manifest: the track's `bmff-hash-map`-style `merkle` entry (root row,
  `count`, `initHash`) plus, per segment, its `bmffMerkleMap` proof.
- `../../../../js/merkle-core.js` — the tree/proof algorithm (box
  exclusion, tree construction, proof building, proof reconstruction), with
  no crypto built in so it runs under both WebCrypto and `node:crypto`.
- `../../../../js/merkle.js` — browser wrapper (WebCrypto) used by the demo
  page: `C2PAMerkle.verifySegment(manifest, segmentId, bytes)`.
- `../../../../scripts/build-merkle-manifest.js` — regenerates
  `video_merkle_manifest.json` from the `.m4s` files (`npm run
  build-merkle-manifest`).
- `../../../../scripts/verify-merkle-manifest.js` — standalone Node
  self-test: reconstructs the root for all 20 segments and runs a
  single-byte tamper check (`npm run verify-merkle-manifest`).

## Verification steps (what `C2PAMerkle.verifySegment` does)

1. Parse the segment's raw bytes as top-level ISO-BMFF boxes.
2. Concatenate every box except `ftyp`, `mfra`, and the C2PA `uuid` box —
   this is the leaf's hash input.
3. `leafHash = sha256(that concatenation)`.
4. Look up the segment's proof entry (`location`, ordered sibling
   `hashes`) by `segmentId` in the manifest.
5. Walk `leafHash` up through the proof: at each level, derive from
   `location` and the tree's `count` whether a sibling hash exists at that
   position (see "null node" above) and, if so, whether it's concatenated
   on the left or the right, hashing at each level that has a sibling.
6. Compare the reconstructed hash to `bmffHashAssertion.merkle[0].hashes[0]`
   (the root stored in the manifest). Match → `valid`; mismatch (e.g. any
   byte in the segment changed) → `invalid`.
