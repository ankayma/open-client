// Dependency-free QR code encoder (byte mode, ECC level M, versions 1–10).
//
// Why hand-rolled: the GUI repo is PUBLIC, so pulling an npm dep (`qrcode`) is an
// owner-gated supply-chain decision (A.1.21 + CLAUDE.md §4, ledger Queue #9). Same
// precedent as the dep-free DNS responder (RFC1035 hand-roll to dodge the dep gate).
// This module renders a real, scannable QR from an invite URL with zero dependencies.
//
// Scope (honest [A]): byte mode + level M + versions 1–10 (≤180 bytes), which covers
// every `ankayma://join…` / `ankayma://join-team…` link. Larger payloads throw rather
// than silently truncate. Correctness is structural here; the live scan is human-QC.

// ── Galois field GF(256), primitive 0x11d ──────────────────────────────────────
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

// Reed–Solomon divisor of the given degree: a monic polynomial's coefficients,
// highest power first, with the implicit leading 1 dropped (Nayuki convention).
function rsDivisor(degree: number): number[] {
  const result = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

// EC codewords for one data block. Exported for the encoder's known-answer test.
export function rsEncode(data: number[], ecLen: number): number[] {
  const divisor = rsDivisor(ecLen);
  const res = new Array(ecLen).fill(0);
  for (const d of data) {
    const factor = d ^ res[0];
    res.shift();
    res.push(0);
    for (let i = 0; i < ecLen; i++) res[i] ^= gfMul(divisor[i], factor);
  }
  return res;
}

// ── Version tables (ECC level M) ───────────────────────────────────────────────
// [totalDataCodewords, ecPerBlock, g1Blocks, g1DataCw, g2Blocks, g2DataCw]
const VERSIONS: Record<number, [number, number, number, number, number, number]> = {
  1: [16, 10, 1, 16, 0, 0],
  2: [28, 16, 1, 28, 0, 0],
  3: [44, 26, 1, 44, 0, 0],
  4: [64, 18, 2, 32, 0, 0],
  5: [86, 24, 2, 43, 0, 0],
  6: [108, 16, 4, 27, 0, 0],
  7: [124, 18, 4, 31, 0, 0],
  8: [154, 22, 2, 38, 2, 39],
  9: [182, 22, 3, 36, 2, 37],
  10: [216, 26, 4, 43, 1, 44],
};

// Alignment-pattern centre coordinates per version (besides the finder corners).
const ALIGN: Record<number, number[]> = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
};

// Remainder bits appended after the interleaved codeword stream.
const REMAINDER: Record<number, number> = {
  1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0,
};

function pickVersion(byteLen: number): number {
  for (let v = 1; v <= 10; v++) {
    const total = VERSIONS[v][0];
    const countBits = v >= 10 ? 16 : 8;
    const capacity = Math.floor((total * 8 - 4 - countBits) / 8);
    if (byteLen <= capacity) return v;
  }
  throw new Error(`QR payload too large (${byteLen} bytes > v10 capacity)`);
}

// ── Bit buffer ─────────────────────────────────────────────────────────────────
class Bits {
  bits: number[] = [];
  push(value: number, len: number) {
    for (let i = len - 1; i >= 0; i--) this.bits.push((value >> i) & 1);
  }
}

// Encode the payload into the final interleaved codeword stream for `version`.
function encodeBytes(bytes: Uint8Array, version: number): number[] {
  const [total, ecLen, g1n, g1d, g2n, g2d] = VERSIONS[version];
  const countBits = version >= 10 ? 16 : 8;

  const bb = new Bits();
  bb.push(0b0100, 4); // byte mode
  bb.push(bytes.length, countBits);
  for (const b of bytes) bb.push(b, 8);

  // Terminator (≤4 zero bits) then pad to byte boundary.
  const totalBits = total * 8;
  const term = Math.min(4, totalBits - bb.bits.length);
  bb.push(0, term);
  while (bb.bits.length % 8 !== 0) bb.bits.push(0);

  // Codewords + alternating pad bytes 0xEC / 0x11.
  const dataCw: number[] = [];
  for (let i = 0; i < bb.bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bb.bits[i + j];
    dataCw.push(byte);
  }
  const PAD = [0xec, 0x11];
  let p = 0;
  while (dataCw.length < total) dataCw.push(PAD[p++ % 2]);

  // Split into blocks, compute EC per block.
  const blocks: { data: number[]; ec: number[] }[] = [];
  let off = 0;
  for (let i = 0; i < g1n; i++) {
    const data = dataCw.slice(off, off + g1d);
    off += g1d;
    blocks.push({ data, ec: rsEncode(data, ecLen) });
  }
  for (let i = 0; i < g2n; i++) {
    const data = dataCw.slice(off, off + g2d);
    off += g2d;
    blocks.push({ data, ec: rsEncode(data, ecLen) });
  }

  // Interleave data codewords, then EC codewords.
  const out: number[] = [];
  const maxData = Math.max(g1d, g2d);
  for (let i = 0; i < maxData; i++) {
    for (const blk of blocks) if (i < blk.data.length) out.push(blk.data[i]);
  }
  for (let i = 0; i < ecLen; i++) {
    for (const blk of blocks) out.push(blk.ec[i]);
  }
  return out;
}

// ── Matrix construction ────────────────────────────────────────────────────────
type Grid = (boolean | null)[][];

function newGrid(size: number): Grid {
  return Array.from({ length: size }, () => new Array(size).fill(null));
}

function placeFinder(g: Grid, row: number, col: number) {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const rr = row + r;
      const cc = col + c;
      if (rr < 0 || cc < 0 || rr >= g.length || cc >= g.length) continue;
      const inner =
        (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
        (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
        (r >= 2 && r <= 4 && c >= 2 && c <= 4);
      g[rr][cc] = inner;
    }
  }
}

function placeAlignment(g: Grid, version: number) {
  const centres = ALIGN[version];
  for (const r of centres) {
    for (const c of centres) {
      // Skip the three finder corners.
      if (
        (r === 6 && c === 6) ||
        (r === 6 && c === g.length - 7) ||
        (r === g.length - 7 && c === 6)
      )
        continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const ring = Math.max(Math.abs(dr), Math.abs(dc));
          g[r + dr][c + dc] = ring !== 1;
        }
      }
    }
  }
}

function reserveFormat(g: Grid) {
  const n = g.length;
  for (let i = 0; i < 9; i++) {
    if (g[8][i] === null) g[8][i] = false;
    if (g[i][8] === null) g[i][8] = false;
  }
  for (let i = 0; i < 8; i++) {
    if (g[8][n - 1 - i] === null) g[8][n - 1 - i] = false;
    if (g[n - 1 - i][8] === null) g[n - 1 - i][8] = false;
  }
  g[n - 8][8] = true; // fixed dark module
}

function placeFunctionPatterns(version: number): { grid: Grid; reserved: boolean[][] } {
  const size = 17 + version * 4;
  const g = newGrid(size);

  placeFinder(g, 0, 0);
  placeFinder(g, 0, size - 7);
  placeFinder(g, size - 7, 0);

  // Separators are the null cells the finder loop left as false at its border —
  // ensure the one-module separator ring is light.
  for (let i = 0; i < 8; i++) {
    if (g[7][i] === null) g[7][i] = false;
    if (g[i][7] === null) g[i][7] = false;
    if (g[7][size - 1 - i] === null) g[7][size - 1 - i] = false;
    if (g[i][size - 8] === null) g[i][size - 8] = false;
    if (g[size - 8][i] === null) g[size - 8][i] = false;
    if (g[size - 1 - i][7] === null) g[size - 1 - i][7] = false;
  }

  // Timing patterns.
  for (let i = 8; i < size - 8; i++) {
    if (g[6][i] === null) g[6][i] = i % 2 === 0;
    if (g[i][6] === null) g[i][6] = i % 2 === 0;
  }

  placeAlignment(g, version);
  reserveFormat(g);

  // Snapshot which cells are function modules (cannot carry data or be masked).
  const reserved = g.map((row) => row.map((cell) => cell !== null));
  return { grid: g, reserved };
}

function placeData(g: Grid, reserved: boolean[][], stream: number[], remainder: number) {
  const n = g.length;
  const bits: number[] = [];
  for (const cw of stream) for (let i = 7; i >= 0; i--) bits.push((cw >> i) & 1);
  for (let i = 0; i < remainder; i++) bits.push(0);

  let idx = 0;
  let upward = true;
  for (let col = n - 1; col > 0; col -= 2) {
    if (col === 6) col = 5; // skip the vertical timing column
    for (let i = 0; i < n; i++) {
      const row = upward ? n - 1 - i : i;
      for (let c = 0; c < 2; c++) {
        const cc = col - c;
        if (reserved[row][cc]) continue;
        g[row][cc] = idx < bits.length ? bits[idx] === 1 : false;
        idx++;
      }
    }
    upward = !upward;
  }
}

const MASKS: ((r: number, c: number) => boolean)[] = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function applyMask(g: Grid, reserved: boolean[][], mask: number): Grid {
  const fn = MASKS[mask];
  return g.map((row, r) =>
    row.map((cell, c) => (reserved[r][c] ? cell : (cell ? true : false) !== fn(r, c))),
  );
}

// Penalty score (lower = better) per the QR spec's four rules.
function penalty(g: Grid): number {
  const n = g.length;
  const m = g.map((row) => row.map((c) => c === true));
  let score = 0;

  // Rule 1: runs of ≥5 same-colour modules in rows and columns.
  for (let r = 0; r < n; r++) {
    for (let dir = 0; dir < 2; dir++) {
      let run = 1;
      for (let c = 1; c < n; c++) {
        const a = dir === 0 ? m[r][c] : m[c][r];
        const b = dir === 0 ? m[r][c - 1] : m[c - 1][r];
        if (a === b) {
          run++;
        } else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) score += 3 + (run - 5);
    }
  }

  // Rule 2: 2×2 blocks of the same colour.
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const v = m[r][c];
      if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) score += 3;
    }
  }

  // Rule 3: finder-like 1:1:3:1:1 patterns in rows and columns.
  const pat1 = [true, false, true, true, true, false, true, false, false, false, false];
  const pat2 = [false, false, false, false, true, false, true, true, true, false, true];
  for (let r = 0; r < n; r++) {
    for (let c = 0; c <= n - 11; c++) {
      let h1 = true, h2 = true, v1 = true, v2 = true;
      for (let k = 0; k < 11; k++) {
        if (m[r][c + k] !== pat1[k]) h1 = false;
        if (m[r][c + k] !== pat2[k]) h2 = false;
        if (m[c + k][r] !== pat1[k]) v1 = false;
        if (m[c + k][r] !== pat2[k]) v2 = false;
      }
      if (h1 || h2) score += 40;
      if (v1 || v2) score += 40;
    }
  }

  // Rule 4: deviation of the dark-module ratio from 50%.
  let dark = 0;
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (m[r][c]) dark++;
  const pct = (dark * 100) / (n * n);
  score += Math.floor(Math.abs(pct - 50) / 5) * 10;
  return score;
}

// Format info: ECC level M ("00") + 3-bit mask, BCH(15,5), masked with 0x5412.
function formatBits(mask: number): number[] {
  const data = (0b00 << 3) | mask;
  let rem = data << 10;
  for (let i = 14; i >= 10; i--) {
    if ((rem >> i) & 1) rem ^= 0b10100110111 << (i - 10);
  }
  const bits = ((data << 10) | rem) ^ 0b101010000010010;
  const out: number[] = [];
  for (let i = 14; i >= 0; i--) out.push((bits >> i) & 1);
  return out;
}

function placeFormat(g: Grid, mask: number) {
  const n = g.length;
  const f = formatBits(mask);
  // Around the top-left finder.
  for (let i = 0; i <= 5; i++) g[8][i] = f[i] === 1;
  g[8][7] = f[6] === 1;
  g[8][8] = f[7] === 1;
  g[7][8] = f[8] === 1;
  for (let i = 9; i < 15; i++) g[14 - i][8] = f[i] === 1;
  // Mirror copy by the top-right and bottom-left finders.
  for (let i = 0; i <= 7; i++) g[n - 1 - i][8] = f[i] === 1;
  for (let i = 8; i < 15; i++) g[8][n - 15 + i] = f[i] === 1;
  g[n - 8][8] = true; // re-assert the dark module
}

export interface QrMatrix {
  size: number;
  modules: boolean[][];
}

// Encode `text` into a QR module matrix (true = dark). Throws if it exceeds v10.
export function encodeQR(text: string): QrMatrix {
  const bytes = new TextEncoder().encode(text);
  const version = pickVersion(bytes.length);
  const stream = encodeBytes(bytes, version);

  const { grid, reserved } = placeFunctionPatterns(version);
  placeData(grid, reserved, stream, REMAINDER[version]);

  let best: Grid | null = null;
  let bestMask = 0;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const candidate = applyMask(grid, reserved, mask);
    placeFormat(candidate, mask);
    const s = penalty(candidate);
    if (s < bestScore) {
      bestScore = s;
      best = candidate;
      bestMask = mask;
    }
  }
  const out = best as Grid;
  placeFormat(out, bestMask);

  return {
    size: out.length,
    modules: out.map((row) => row.map((c) => c === true)),
  };
}
