# ChessSteg — Complete System Architecture & Codebase Guide

This document provides a comprehensive, end-to-end technical reference for **ChessSteg — Deterministic Chess PGN Steganography Engine & Move-by-Move Game Review Ledger**. It documents every file, algorithm, cryptographic framing formula, move-scoring heuristic, PGN formatting/parsing rule, REST API contract, React UI structure, and automated unit test in the repository.

---

## 1. Repository File Tree & Single-Runtime Architecture

ChessSteg runs on a single unified TypeScript/Node.js stack (`server.ts` + `src/engine/chessSteg.ts` + `src/App.tsx`). All legacy secondary files and unused directories have been removed.

```text
/
├── .env.example                              # Environment variable template
├── .gitignore                                # Git ignore rules
├── SYSTEM_ARCHITECTURE_AND_CODEBASE_GUIDE.md # Complete system documentation
├── bun.lock                                  # Dependency lockfile
├── index.html                                # HTML entry point
├── metadata.json                             # Applet metadata
├── package.json                              # Scripts and dependencies (chess.js, express, react, vite)
├── server.ts                                 # Express + Vite middleware server (/api/encode, /api/decode, /api/avalanche)
├── tsconfig.json                             # TypeScript configuration
├── vite.config.ts                            # Vite configuration
└── src/
    ├── App.tsx                               # Minimalist React frontend (Encode/Decode, Board, Controls, Ledger)
    ├── index.css                             # Tailwind CSS import (@import "tailwindcss";)
    ├── main.tsx                              # React DOM entry point
    └── engine/
        ├── chessSteg.ts                      # Core deterministic steganography & chess heuristic engine
        └── chessSteg.test.ts                 # 9 automated unit tests (node:test)
```

---

## 2. Cryptographic Bitstream Framing (`encodeBitstream` & `decodeBitstream`)

ChessSteg embeds arbitrary UTF-8 payloads into legal chess moves without using PGN headers, comments, or external metadata. It uses a **32-bit header + $8N$-bit payload** framing scheme with counter-mode SHA-256 XOR masking so that:
1. **Avalanche Effect:** Changing even 1 character at the very end of the message alters the 16-bit seed at bits `0..15`, producing a completely different chess game starting at Ply 1.
2. **Length Header Obfuscation:** Two different messages of the exact same byte length do not share identical bits at bit offsets `16..31`.
3. **Optional Passphrase Binding:** Users can optionally supply a shared passphrase; without the matching passphrase, both the length header and payload unmask to pseudorandom bytes and fail integrity verification.
4. **Tamper Detection (16-Bit Checksum):** Modifying any move in the PGN (or supplying an incorrect passphrase) is caught upon decoding.

### 2.1 Packet Layout
$$\text{Packet} = \underbrace{\text{Seed}}_{16\text{ bits (2 B)}} \;\Vert\; \underbrace{\text{ScrambledLength}}_{16\text{ bits (2 B)}} \;\Vert\; \underbrace{\text{ScrambledPayload}}_{8N\text{ bits (}N\text{ B)}}$$

### 2.2 Encoding Formulas (`encodeBitstream(text, passphrase = '')`)
1. **UTF-8 Buffers:**
   - `raw = Buffer.from(text, 'utf-8')` ($0 \le N \le 65535$ bytes)
   - `keyMaterial = Buffer.from(passphrase, 'utf-8')`
2. **16-Bit Avalanche Seed (`Bits 0..15`):**
   $$\text{seed} = \text{SHA-256}(\text{raw} \;\Vert\; \text{keyMaterial})[0..1]$$
3. **16-Bit Scrambled Length Header (`Bits 16..31`):**
   - `lenBuf` = 2-byte big-endian unsigned integer of `raw.length` (`writeUInt16BE`)
   - $\text{lenMask} = \text{SHA-256}(\text{seed} \;\Vert\; \text{keyMaterial} \;\Vert\; \text{"LEN"})[0..1]$
   - $\text{scrambledLen} = \text{lenBuf} \oplus \text{lenMask}$
4. **Counter-Mode Scrambled Payload (`Bits 32..32+8N-1`):**
   - For each byte index $i \in [0, N - 1]$:
     - `idxBuf` = 2-byte big-endian unsigned integer of $i$ (`writeUInt16BE(i, 0)`)
     - $\text{maskByte}_i = \text{SHA-256}(\text{seed} \;\Vert\; \text{keyMaterial} \;\Vert\; \text{idxBuf})[0]$
     - $\text{scrambled}[i] = \text{raw}[i] \oplus \text{maskByte}_i$
5. **Bitstring Conversion:**
   - `packet = Buffer.concat([seed, scrambledLen, scrambled])` converted MSB-first (`b.toString(2).padStart(8, '0')`) into a binary string of length $32 + 8N$ bits.

### 2.3 Decoding & Integrity Verification (`decodeBitstream(bits, passphrase = '')`)
1. Requires `bits.length >= 32`. Extracts `seed` (`bits[0..15]`) and `scrambledLen` (`bits[16..31]`).
2. Computes $\text{lenMask} = \text{SHA-256}(\text{seed} \;\Vert\; \text{keyMaterial} \;\Vert\; \text{"LEN"})[0..1]$ and unmasks `lenBuf = scrambledLen ^ lenMask` to obtain `msgLen` (`readUInt16BE(0)`).
3. Computes `totalNeeded = 32 + msgLen * 8`. If `bits.length < totalNeeded`, throws:
   ```text
   Integrity or length check failed: Incorrect passphrase, tampered PGN moves, or truncated PGN (unmasked header requested <msgLen> bytes / <totalNeeded> bits, but PGN has <bits.length> bits).
   ```
4. Unmasks each payload byte $i \in [0, \text{msgLen} - 1]$ using $\text{maskByte}_i = \text{SHA-256}(\text{seed} \;\Vert\; \text{keyMaterial} \;\Vert\; \text{idxBuf})[0]$.
5. **Checksum Verification:** Recomputes $\text{expectedSeed} = \text{SHA-256}(\text{raw} \;\Vert\; \text{keyMaterial})[0..1]$. If `!expectedSeed.equals(seed)`, throws:
   ```text
   Integrity check failed: PGN moves were altered or passphrase is incorrect.
   ```

---

## 3. Deterministic Chess Move Scorer (`scoreMove` & `getCandidateMoves`)

To remain 100% deterministic across platforms without external Stockfish binaries or WASM dependencies, ChessSteg evaluates every legal move at the current board state using a pure positional and tactical heuristic function `scoreMove(board, move, recentFens)`.

### 3.1 Piece Material Table (`PIECE_VALUES`)
- Pawn (`p`): `100`
- Knight (`n`): `320`
- Bishop (`b`): `330`
- Rook (`r`): `500`
- Queen (`q`): `900`
- King (`k`): `20000`

### 3.2 Heuristic Rules & Exact Weights in `scoreMove`
1. **Capture Value (MVV-LVA):**
   - If `move.captured` is present:
     $$\text{score} \mathrel{+}= \text{victimVal} \times 10 - \lfloor \text{attackerVal} / 10 \rfloor$$
2. **Pawn Promotion & Underpromotion Filter:**
   - If `move.promotion === 'q'`: **`+900`** (`+PIECE_VALUES.q`).
   - If `move.promotion` is `'r'`, `'b'`, or `'n'` (underpromotion): **`-1000`** (prevents underpromotions from flooding the Top-4 candidate pool).
3. **Center-Square Control:**
   - `INNER_CENTER` (`d4`, `d5`, `e4`, `e5`): **`+45`**
   - `OUTER_CENTER` (`c4`, `c5`, `d3`, `d6`, `e3`, `e6`): **`+25`**
4. **Threatened-Piece Rescue Bonus:**
   - Before making the move, checks if `move.from` is currently attacked by the opponent (`board.isAttacked(move.from, opponentPre)`).
   - If attacked: **`+Math.floor(attackerVal * 2)`** (rewards retreating/rescuing an attacked piece to a safe square; if the destination square is also attacked, the post-move `-attackerVal * 9` penalty overrides this bonus).
5. **Minor Piece Development & Opening Discipline (`n`, `b`):**
   - Leaving `homeRank` (`fromRank === homeRank && toRank !== homeRank`): **`+50`**
   - Destination file centrality (`allowCentralityBonus = fullMoveNumber > 8 || fromRank === homeRank || Boolean(move.captured)`):
     - Central files (`c`, `d`, `e`, `f`): **`+20`** (when `allowCentralityBonus` is true)
     - Semi-central files (`b`, `g`): **`+5`** (when `allowCentralityBonus` is true)
     - Rim files (`a`, `h`): **`-30`** (always applied)
   - Moving an already-developed minor piece a second time in the opening (`fullMoveNumber <= 8 && fromRank !== homeRank && !move.captured && !isFromAttacked`): **`-30`** (encourages developing remaining back-rank pieces and castling first).
6. **Pawn Advances & Opening Pawn Structure (`p`):**
   - Forward rank advance (`advance * 8`): **`+8`** for a 1-square push, **`+16`** for a 2-square double push.
   - Classical 2-square central opening pawn pushes (`d2d4`, `e2e4`, `d7d5`, `e7e5`): **`+15`** additional bonus (bringing `d4` and `e4` to `+45 + 16 + 15 = +76` on Move 1, ahead of `Nc3`/`Nf3` at `+70`).
   - Opening non-capture flank/king-safety penalties (`fullMoveNumber <= 10 && !move.captured`):
     - Moving the `f2` or `f7` pawn: **`-25`**
     - Moving an `a`-file or `h`-file pawn: **`-20`**
7. **King Safety & Castling:**
   - Castling (`O-O` or `O-O-O`): **`+75`**
   - Early Queen development off `homeRank` (`fullMoveNumber <= 10`): **`-40`**
   - Early non-castling King move (`fullMoveNumber <= 10`): **`-60`**
8. **Check Bonus:**
   - Move SAN contains `+` or `#`: **`+30`**
9. **Post-Move Simulation Checks (`board.move(move)` $\rightarrow$ evaluate $\rightarrow$ `board.undo()`):**
   - **Premature Game-Over Avoidance:** If `board.isGameOver()` is true (checkmate, stalemate, or draw): **`-50000`** (prevents ending the carrier game early whenever non-terminal legal moves exist).
   - **Position Repetition Penalty:** If `recentFens.has(getPositionFenKey(board))`: **`-600`** (prevents pieces from shuffling back and forth between the same squares).
   - **Destination Hang / Blunder Penalty:** If `board.isAttacked(move.to, opponentColor)`: **`-attackerVal * 9`** (heavily penalizes moving into an attacked square or making a losing capture like `Qxd5` into a defended pawn, while keeping equal trades such as `pxp` (`+90`) and `NxN` (`+288`) net positive).

### 3.3 Candidate Pool Selection (`getCandidateMoves`)
1. Scores all legal moves and sorts them in descending order of `score`, breaking ties deterministically by ascending alphabetical `uci` (`a.uci.localeCompare(b.uci)`).
2. Selects the pool size $K \in \{4, 2, 1\}$:
   - If $\ge 4$ legal moves exist: returns top **4** moves (**2 bits** per ply: `00`, `01`, `10`, `11`).
   - If $2$ or $3$ legal moves exist: returns top **2** moves (**1 bit** per ply: `0`, `1`).
   - If $1$ legal move exists (forced move): returns **1** move (**0 bits** consumed/emitted).

On Move 1 for White, the Top-4 candidate pool is deterministically:
- `00`: `d4` (`+76`)
- `01`: `e4` (`+76`)
- `10`: `Nc3` (`+70`)
- `11`: `Nf3` (`+70`)

---

## 4. PGN Formatting, Multi-Game Chaining & Lichess Decode Tolerance

### 4.1 Standard Result Tokens & 80-Column Wrapping (`runEncode`)
- If a game reaches a terminal board state (`board.isGameOver()`) before all message bits are embedded, `runEncode` records the finished game and initializes a new `Chess()` board (`game_index + 1`) until `bitCursor >= totalBits`.
- At the end of each game, `getGameResultToken(board)` appends:
  - `'1-0'` if White delivered checkmate
  - `'0-1'` if Black delivered checkmate
  - `'1/2-1/2'` if the game ended in stalemate or draw
  - `'*'` if the bitstream completed while the game was still in progress
- `formatGameMovesToPgn` wraps each game's movetext (including the trailing result token) at a maximum of **80 characters per line** separated by `\n`, and joins chained games with `\n\n`.

### 4.2 Robust PGN Splitting (`splitPgnIntoMoveLists`)
- Strips PGN header tags (`[Event "..."]`), brace comments (`{...}`), and line comments (`;...`).
- Splits multiple games only on explicit PGN termination tokens (`1-0`, `0-1`, `1/2-1/2`, `*`) or whitespace immediately followed by Move 1 of a new game (`\s+(?=1\.\s+[A-Za-z])`), so accidental mid-game blank lines (`\n\n`) never break a single game in half.

### 4.3 Trailing Non-Payload Move Tolerance (`runDecode`)
- During `runDecode`, once `totalBitsExtracted >= 32`, `unmaskHeaderTotalBits` unmasks the 32-bit header to determine `headerTotalNeeded = 32 + msgLen * 8`.
- As soon as `totalBitsExtracted >= headerTotalNeeded`, `runDecode` tests `decodeBitstream(bits.slice(0, headerTotalNeeded), passphrase)`.
- If and only if the seed checksum succeeds at `headerTotalNeeded`, `payloadComplete` is set to `true`. Any subsequent trailing legal moves (e.g., extra moves played on a Lichess analysis board after the hidden message finished) do not throw candidate-pool errors and are recorded in `frames` with `bits: '—'`.

---

## 5. Backend REST API (`server.ts`) & Frontend (`src/App.tsx`)

### 5.1 Express API Endpoints (`server.ts`, Port `3000`)
- **`POST /api/encode`**: Accepts `{ text: string, passphrase?: string }`, returns `EncodeResult`.
- **`POST /api/decode`**: Accepts `{ pgn: string, passphrase?: string }`, returns `DecodeResult`.
- **`POST /api/avalanche`**: Accepts `{ text_a: string, text_b: string, passphrase?: string }`, returns `AvalancheResult` (Hamming distance percentage, first divergent ply, and ply-by-ply comparison).

### 5.2 Minimalist React Frontend (`src/App.tsx`)
- **Encode / Decode Forms:** Plaintext textarea, optional passphrase input, `Encode` button, PGN textarea, `Decode` button, one-click `[ COPY PGN ]` button, and decoded plaintext output.
- **Interactive 8x8 Board & Transport Controls:** Fixed `w-80 h-80` 8x8 Unicode chessboard (`grid-cols-8 grid-rows-8`), 5 Lucide icon transport buttons (`START`, `PREV`, `NEXT`, `END`, `PLAY`/`STOP`), keyboard `ArrowLeft`/`ArrowRight` navigation, and a 4-column Candidate Move Pool bar (`data-testid="candidate-pool"`) highlighting the chosen move in `#D9381E`.
- **Move & Bitstream Ledger Table:** Scrollable table displaying `Ply`, `Game`, `Move`, `SAN`, `UCI`, `Bits`, and `Pool` for every ply, with `// GAME 02 — NEW BOARD INITIALIZED` separator rows whenever `game_index` increments.

---

## 6. Automated Unit Test Suite (`src/engine/chessSteg.test.ts`)

Run via `npx tsx --test src/engine/chessSteg.test.ts` (9 tests):
1. **`bitstream packing scrambles length header and verifies 16-bit seed checksum`**: Verifies two same-length messages produce different scrambled `length_bits` and round-trip cleanly.
2. **`passphrase-bound steganography and checksum tamper rejection`**: Verifies passphrase-protected encoding decodes with the matching passphrase and throws an integrity/length check error with a wrong passphrase.
3. **`avalanche effect: 1-character change at end alters 16-bit seed and diverges at Ply 1`**: Verifies a 1-character change at the end of a message alters `seed_hex`, flips $>30\%$ of bits, and diverges at Ply 1.
4. **`chess heuristics: central pawns (d4/e4) and central knights (Nc3/Nf3) rank #1-#4 on Move 1`**: Verifies Move 1 top-4 candidates are `['d4', 'e4', 'Nc3', 'Nf3']` in exact order, excluding `Na3` and `f4`.
5. **`chess heuristics: Queen does not blunder into a defended pawn`**: Verifies `Qxd5` into a pawn defended by `e6` receives a score $< -5000$.
6. **`chess heuristics: threatened high-value piece receives rescue bonus to move to a safe square`**: Verifies an attacked Knight on `f3` receives a rescue bonus ($> +600$) to retreat to `d2`, outscoring non-rescue moves.
7. **`robust PGN splitting handles accidental mid-game blank lines, headers, and comments`**: Verifies PGNs with `[Event "..."]` headers, `{...}` comments, mid-game `\n\n` blank lines, and `*` decode accurately.
8. **`PGN output includes standard result token, 80-column wrapping, and ignores trailing Lichess moves on decode`**: Verifies PGN result tokens, $\le 80$-character line wrapping, and decoding when non-candidate legal moves are appended after payload completion.
9. **`chess heuristics: underpromotions (=R, =B, =N) are excluded from Top-4 pool and premature game-ending moves are penalized`**: Verifies `a8=Q+` ranks #1 while `=R`, `=B`, `=N` are excluded from the Top-4 pool, and premature checkmate (`Qxf7#`) is excluded when non-terminal moves exist.
