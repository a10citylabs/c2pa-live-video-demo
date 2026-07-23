# C2PA Live Segment Verification Demo

A minimal web demo that plays a DASH stream with [dash.js](https://github.com/Dash-Industry-Forum/dash.js) **v5.2.0** (latest release) and cryptographically verifies the **C2PA manifest embedded in every media segment** while it plays, showing a *Content Credentials* overlay with the live verification state.

The content is the sample in
[`samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method`](samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method):
20 fMP4 video segments, each carrying its own C2PA manifest store (JUMBF) in a top-level `uuid` box, plus the decoded reference manifest [`example_c2pa_manifest.json`](samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/example_c2pa_manifest.json).

## Run it

```sh
npm install && npm start          # http-server on http://localhost:8000
# or, with no install at all:
python3 -m http.server 8000
```

Open <http://localhost:8000/> in any browser with H.264 playback (Chrome, Edge, Firefox, Safari). The page also works when hosted statically (e.g. GitHub Pages).

## What happens

1. dash.js 5.2.0 (vendored in [`lib/`](lib), pinned in `package.json`) plays [`stream.mpd`](samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/stream.mpd).
2. A dash.js **response interceptor** hands every media segment's bytes to [`js/c2pa.js`](js/c2pa.js) before they reach the media pipeline.
3. For each segment, following [`C2PA-Live-Segment-Validation.md`](samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/C2PA-Live-Segment-Validation.md):
   - the C2PA manifest store is extracted from the segment's `uuid` box (JUMBF + CBOR parsing, no external libraries);
   - the `c2pa.IVHASH` assertion yields `segmentId`, `anchorSegmentIndex`, `streamIdHash`, `certHash` and the expected `continuityToken`;
   - the per-segment IV is derived from the anchor segment — `sha256(streamIdHash + anchorNumber)[0..16]`, incremented once per segment after the anchor;
   - the segment's `moof`+`mdat` bytes are AES-128-CBC encrypted (key = first 16 chars of `certHash`, WebCrypto) and the last ciphertext block, base64-encoded, is compared against the `continuityToken`.
4. The **Content Credentials overlay** (the `cr` badge on the video) reflects the segment currently playing: signer (from the COSE `x5chain` certificate), claim generator, author, assertion list, expected vs. computed token, derived IV and timing. The strip under the player shows the state of all 20 segments.

### Demo controls

- **`cr` badge** — toggles the Content Credentials panel.
- **View manifest / verification JSON** — decoded embedded manifest + verification result of the current segment.
- **Tamper next segment** — flips one byte in the next fetched segment's `mdat` so the continuity check fails; the overlay and segment strip turn red. (When the reference `example_c2pa_manifest.json` segment `803366` plays, the panel also cross-checks it against the embedded manifest.)

## Repository layout

```
index.html      demo page (UI + overlay)
js/c2pa.js      ISO-BMFF/JUMBF/CBOR parsing + continuity-token verification (WebCrypto)
js/app.js       dash.js wiring, interceptor, overlay rendering
lib/            dash.js 5.2.0 UMD build (vendored; `npm run sync-dashjs` refreshes it)
samples/live-streaming/Video/Per-segment-C2PA-Manifest-Box-method/
  ├── C2PA-Live-Segment-Validation.md   verification method documentation
  ├── example_c2pa_manifest.json        decoded reference manifest (segment 803366)
  ├── stream.mpd                        DASH manifest for the sample segments
  ├── m4s/                              video segments 803347–803366 + init.mp4
  └── mp4/                              audio-track segments (same embedded-manifest method)
```

Notes on the media: the sample ships bare media segments (no initialization segment), so `m4s/init.mp4` and `stream.mpd` were reconstructed from the bitstream (H.264 Constrained Baseline, 320×180 @ 24 fps, timescale 12288, `avc1.42C01E`). Verification itself never touches the reconstructed files — it runs on the untouched segment bytes. The `mp4/` audio segments embed manifests the same way and verify with the same code, but are not part of playback (their capture window differs from the video's).

## Credits

- The live-segment continuity verification approach is based on Adobe Research's paper
  [Integrating Content Authenticity with DASH Video Streaming](https://research.adobe.com/publication/integrating-content-authenticity-with-dash-video-streaming/).
- More C2PA-signed sample video segments for testing are available from the
  [c2pa-org/public-testfiles](https://github.com/c2pa-org/public-testfiles) repository.

## Licenses

- dash.js is © Dash Industry Forum, BSD-3-Clause — see [LICENSE.md](LICENSE.md) and [`lib/dash.all.min.js.LICENSE.txt`](lib/dash.all.min.js.LICENSE.txt).
- The sample video content shows Big Buck Bunny © Blender Foundation, [bigbuckbunny.org](https://peach.blender.org/) (CC-BY 3.0).
