# ChessSteg — Deterministic Chess PGN Steganography Engine & Move-by-Move Game Review Ledger

**ChessSteg** is a full-stack steganography engine and interactive chess game reviewer that hides arbitrary UTF-8 text messages inside valid, human-plausible Portable Game Notation (PGN) chess games—without using PGN header tags, comments, annotations, or external Stockfish binaries.

Every legal move in a generated game embeds up to **2 bits** of a cryptographically scrambled bitstream by selecting from the **Top-4 deterministically scored candidate moves** at each ply. Because the message's 16-bit SHA-256 avalanche seed is embedded in the very first moves of the game and masks both the 16-bit length header and payload bytes, **changing a single character anywhere in the message produces an entirely different chess game starting from Move 1**.

---

## Table of Contents

1. [Key Features](#1-key-features)
2. [How It Works: End-to-End Pipeline](#2-how-it-works-end-to-end-pipeline)
   - [2.1 Reversible Avalanche Bitstream Framing](#21-reversible-avalanche-bitstream-framing)
   - [2.2 Optional Passphrase Binding & Tamper Checksum](#22-optional-passphrase-binding--tamper-checksum)
   - [2.3 Deterministic Heuristic Move Scorer](#23-deterministic-heuristic-move-scorer)
   - [2.4 Candidate Pool Selection & Bit Mapping](#24-candidate-pool-selection--bit-mapping)
   - [2.5 Multi-Game Chaining & Lichess Compatibility](#25-multi-game-chaining--lichess-compatibility)
3. [Interactive Game Review UI](#3-interactive-game-review-ui)
4. [Project Structure](#4-project-structure)
5. [Getting Started & Commands](#5-getting-started--commands)
6. [REST API Reference](#6-rest-api-reference)
7. [Automated Test Suite](#7-automated-test-suite)

---

## 1. Key Features

- **Zero Metadata Footprint:** Secrets are encoded strictly inside standard algebraic move choices (`1. d4 Nf6 2. Nc3 d5 ...`). PGN headers (`[Event "..."]`), comments (`{...}`), and NAGs (`$1`) are never used to store data and can be freely stripped or added without breaking decoding.
- **Full-Message Avalanche Effect:** A 16-bit SHA-256 digest of the entire plaintext (plus optional passphrase) is placed at the head of the bitstream (`Bits 0..15`) and used to XOR-mask the 16-bit length header (`Bits 16..31`) and every payload byte (`Bits 32+`). Modifying even the last character of a message alters the opening move at Ply 1.
- **Passphrase-Bound Steganography & 16-Bit Integrity Checksum:** Supports both keyless operation and shared-passphrase protection. Any tampered PGN move or wrong passphrase fails the post-decode 16-bit seed checksum.
- **Pure TypeScript Chess Heuristics (No External Binaries):** Uses `chess.js` and a deterministic positional/tactical evaluation function (`scoreMove`) that prioritizes classical central openings (`d4`, `e4`, `Nc3`, `Nf3`), castling, MVV-LVA captures, and threatened-piece rescues while penalizing hanging pieces, rim knights (`Na3`/`Nh3`), early `f`-pawn pushes, underpromotions, threefold repetitions, and premature game-ending moves.
- **100% Lichess Compatible:**
  - Outputs standard 80-column wrapped PGN movetext with proper game termination tokens (`1-0`, `0-1`, `1/2-1/2`, or `*`).
  - One-click `[ COPY PGN ]` button to paste directly into [lichess.org/paste](https://lichess.org/paste).
  - **Trailing-Move Tolerance:** If you paste an encoded game into Lichess and play additional analysis moves after the hidden payload finishes, ChessSteg still decodes the original message cleanly without throwing candidate-pool errors on the trailing moves.
- **Interactive Move-by-Move Game Reviewer:** Step forward/backward through every ply (`START`, `PREV`, `NEXT`, `END`, `PLAY/STOP`, or `ArrowLeft`/`ArrowRight` keys), inspect the Top-4 candidate moves and their heuristic scores at each board state, and view the exact bits embedded on every move.

---

## 2. How It Works: End-to-End Pipeline

### 2.1 Reversible Avalanche Bitstream Framing

Given a UTF-8 plaintext string `text` ($N$ bytes, where $1 \le N \le 65,535$) and an optional UTF-8 `passphrase` (default `""`):

1. **Raw Byte Buffers:**
   ```ts
   const raw = Buffer.from(text, 'utf-8');
   const keyMaterial = Buffer.from(passphrase, 'utf-8');
   ```
2. **16-Bit Avalanche Seed (`Bits 0..15`):**
   ```ts
   const seed = crypto
     .createHash('sha256')
     .update(Buffer.concat([raw, keyMaterial]))
     .digest()
     .subarray(0, 2);
   ```
3. **16-Bit XOR-Masked Length Header (`Bits 16..31`):**
   The 2-byte big-endian payload length `lenBuf` is masked so two messages of the same length never share identical header bits:
   ```ts
   const lenBuf = Buffer.alloc(2);
   lenBuf.writeUInt16BE(raw.length, 0);
   const lenMask = crypto
     .createHash('sha256')
     .update(Buffer.concat([seed, keyMaterial, Buffer.from('LEN')]))
     .digest()
     .subarray(0, 2);
   const scrambledLen = Buffer.from([
     lenBuf[0] ^ lenMask[0],
     lenBuf[1] ^ lenMask[1],
   ]);
   ```
4. **Counter-Mode XOR-Scrambled Payload (`Bits 32..32+8N-1`):**
   Each payload byte at index $i \in [0, N - 1]$ is XORed with a keystream byte derived from `seed`, `keyMaterial`, and the 2-byte big-endian index `idxBuf`:
   ```ts
   const maskByte = crypto
     .createHash('sha256')
     .update(Buffer.concat([seed, keyMaterial, idxBuf]))
     .digest()[0];
   scrambled[i] = raw[i] ^ maskByte;
   ```
5. **Final Packet Layout:**
   $$\underbrace{\text{seed}}_{\text{16 bits}} \;\Vert\; \underbrace{\text{scrambledLen}}_{\text{16 bits}} \;\Vert\; \underbrace{\text{scrambledPayload}}_{8N\text{ bits}}$$

### 2.2 Optional Passphrase Binding & Tamper Checksum

When decoding a bitstream back into text (`decodeBitstream`):
1. The first 16 bits (`seed`) and next 16 bits (`scrambledLen`) are extracted.
2. `lenMask` is recomputed from `seed + keyMaterial + "LEN"` to unmask `msgLen` (`0..65535`) and calculate `totalNeeded = 32 + msgLen * 8`.
3. If the PGN bitstream has fewer than `totalNeeded` bits (e.g., due to a truncated PGN or an incorrect passphrase unmasking a bogus length), decoding halts with a clear integrity/length error.
4. After unmasking `msgLen` payload bytes into `raw`, the engine recomputes:
   $$\text{expectedSeed} = \text{SHA-256}(\text{raw} \;\Vert\; \text{keyMaterial})[0..1]$$
   If `expectedSeed` does not match `seed`, decoding fails with:
   `Integrity check failed: PGN moves were altered or passphrase is incorrect.`

---

### 2.3 Deterministic Heuristic Move Scorer

At every ply, both the encoder and decoder run the exact same pure evaluation function `scoreMove(board, move, recentFens)` over all legal moves generated by `chess.js`.

#### Piece Material Values (`PIECE_VALUES`)
| Piece | Symbol | Value |
| :--- | :---: | :---: |
| Pawn | `p` | `100` |
| Knight | `n` | `320` |
| Bishop | `b` | `330` |
| Rook | `r` | `500` |
| Queen | `q` | `900` |
| King | `k` | `20000` |

#### Heuristic Scoring Table (`scoreMove`)
| Category | Condition | Score Delta | Purpose |
| :--- | :--- | :---: | :--- |
| **MVV-LVA Capture** | `move.captured` present | `+victimVal * 10 - Math.floor(attackerVal / 10)` | Prioritizes winning material and equal trades |
| **Queen Promotion** | `move.promotion === 'q'` | `+900` | Rewards standard pawn promotion to Queen |
| **Underpromotion Filter** | `move.promotion` in `{'r', 'b', 'n'}` | `-1000` | Prevents `=R`, `=B`, `=N` from flooding the Top-4 pool |
| **Inner Center Control** | `move.to` in `{'d4', 'd5', 'e4', 'e5'}` | `+45` | Encourages classical central occupation |
| **Outer Center Control** | `move.to` in `{'c4', 'c5', 'd3', 'd6', 'e3', 'e6'}` | `+25` | Rewards secondary central control |
| **Threatened-Piece Rescue** | `board.isAttacked(move.from, opponent)` | `+Math.floor(attackerVal * 2)` | Rescues attacked pieces to safe squares |
| **Minor Piece Development** | `n` or `b` leaving `homeRank` (`1` or `8`) | `+50` | Develops Knights and Bishops in the opening |
| **Minor Piece Centrality** | `toFile` in `{'c','d','e','f'}` / `{'b','g'}` / `{'a','h'}` | `+20` / `+5` / `-30` | Prefers `Nc3`/`Nf3` (`+70`) over rim knights `Na3`/`Nh3` (`+20`) |
| **Repeat Minor Move Penalty** | `fullMoveNumber <= 8`, already developed `n`/`b`, non-capture, unattacked | `-30` | Develops remaining back-rank pieces before moving one twice |
| **Pawn Advance** | Forward rank delta (`1` or `2` squares) | `+8 * advance` | Rewards advancing pawns (`+8` single, `+16` double) |
| **Classical Center Push** | `uci` in `{'d2d4', 'e2e4', 'd7d5', 'e7e5'}` | `+15` | Ranks `d4` & `e4` (`+76`) #1 and #2 on Move 1 ahead of `Nc3`/`Nf3` (`+70`) |
| **Opening `f`-Pawn Penalty** | `fullMoveNumber <= 10`, `!move.captured`, `from` in `{'f2', 'f7'}` | `-25` | Prevents weakening King safety with early `f4`/`f5` |
| **Opening Flank Pawn Penalty** | `fullMoveNumber <= 10`, `!move.captured`, `fromFile` in `{'a', 'h'}` | `-20` | Discourages early `a4`/`h4` flank pushes |
| **Castling** | Kingside (`O-O`) or Queenside (`O-O-O`) | `+75` | Strongly prioritizes castling as soon as legal |
| **Early Queen / King Move** | `fullMoveNumber <= 10` (`q` off home rank / non-castle `k`) | `-40` / `-60` | Prevents premature Queen sorties and King walks |
| **Check Bonus** | `move.san` contains `+` or `#` | `+30` | Rewards forcing checks |
| **Premature Game-Over** | Post-move `board.isGameOver()` is `true` | `-50000` | Avoids checkmate/stalemate/draw when non-terminal moves exist |
| **Position Repetition** | Post-move FEN key in `recentFens` | `-600` | Prevents shuffling pieces back and forth |
| **Destination Hang Penalty** | Post-move `board.isAttacked(move.to, opponent)` | `-attackerVal * 9` | Prevents blundering pieces into defended squares |

---

### 2.4 Candidate Pool Selection & Bit Mapping

At each ply, `getCandidateMoves` sorts all legal moves by `(-score, uci)` and selects the top $K$ candidates:

- **$\ge 4$ legal moves ($K = 4$, 2 bits/ply):**
  - Rank #1 $\rightarrow$ `00`
  - Rank #2 $\rightarrow$ `01`
  - Rank #3 $\rightarrow$ `10`
  - Rank #4 $\rightarrow$ `11`
- **$2$ or $3$ legal moves ($K = 2$, 1 bit/ply):**
  - Rank #1 $\rightarrow$ `0`
  - Rank #2 $\rightarrow$ `1`
- **$1$ legal move ($K = 1$, forced move, 0 bits/ply):**
  - Rank #1 $\rightarrow$ `'—'` (0 bits consumed on encode, 0 bits extracted on decode)

On **Move 1 (Ply 1)** from the standard starting position, White's Top-4 candidate pool is always:
1. `00`: **`d4`** (`+76`)
2. `01`: **`e4`** (`+76`)
3. `10`: **`Nc3`** (`+70`)
4. `11`: **`Nf3`** (`+70`)

---

### 2.5 Multi-Game Chaining & Lichess Compatibility

- **Multi-Game Chaining:** If a long secret message requires more plies than a single chess game can provide (i.e., all legal moves result in checkmate, stalemate, threefold repetition, insufficient material, or the 50-move rule), `runEncode` appends the finished game's PGN result token (`1-0`, `0-1`, or `1/2-1/2`) and initializes a fresh board (`Game 2`, `Game 3`, ...) separated by `\n\n` until every bit is embedded.
- **80-Column Wrapping:** Generated PGN movetext is wrapped at $\le 80$ characters per line, matching standard Lichess PGN exports.
- **Lichess Trailing-Move Tolerance:** During `runDecode`, once the 32-bit header is unmasked and `totalBitsExtracted` reaches `32 + msgLen * 8` with a valid `expectedSeed` checksum, the decoder marks `payloadComplete = true`. Any extra legal moves played at the end of the game (for example, continuing analysis on Lichess after pasting the PGN) are rendered on the review board with `bits: '—'` instead of failing candidate-pool validation.

---

## 3. Interactive Game Review UI

The React frontend (`src/App.tsx`) provides a clean, utilitarian interface:

1. **Plaintext to PGN Encoder:** Enter a secret message and an optional passphrase, then click **Encode** to generate the steganographic PGN and load all plies into the review board.
2. **PGN to Plaintext Decoder:** Paste any single-game or multi-game PGN, optionally enter the passphrase, and click **Decode** to verify the checksum, recover the hidden message, and inspect every move. Includes a one-click **`[ COPY PGN ]`** button.
3. **8x8 Review Board & Transport Bar:**
   - Displays the exact board state at any ply (`0` = `START` through `total_plies`).
   - Transport buttons (`START`, `PREV`, `NEXT`, `END`, `PLAY`/`STOP`) and keyboard `ArrowLeft` / `ArrowRight` support.
   - **Candidate Move Pool Bar:** Shows the 4 candidate moves at the active ply along with their bit labels and signed heuristic scores (`00: d4 (+76)`), highlighting the selected move in International Orange (`#D9381E`).
4. **Move & Bitstream Table:** Scrollable ledger pairing every ply with its `Game`, `Move`, `SAN`, `UCI`, embedded `Bits`, and `Pool` size. Clicking any row jumps the board immediately to that ply. Multi-game transitions display a `// GAME 02 — NEW BOARD INITIALIZED` divider row.

---

## 4. Project Structure

```text
/
├── .env.example                              # Environment variable template
├── .gitignore                                # Git ignore rules
├── README.md                                 # Project documentation & usage guide
├── SYSTEM_ARCHITECTURE_AND_CODEBASE_GUIDE.md # Deep-dive architectural specification
├── bun.lock                                  # Package lockfile
├── index.html                                # HTML entry point
├── metadata.json                             # AI Studio applet metadata
├── package.json                              # Scripts and dependencies
├── server.ts                                 # Express + Vite server (port 3000)
├── tsconfig.json                             # TypeScript configuration
├── vite.config.ts                            # Vite bundler configuration
└── src/
    ├── App.tsx                               # React game reviewer & encode/decode UI
    ├── index.css                             # Tailwind CSS entry point
    ├── main.tsx                              # React root mount
    └── engine/
        ├── chessSteg.ts                      # Core bitstream + heuristic chess steganography engine
        └── chessSteg.test.ts                 # 9 automated unit tests (node:test)
```

---

## 5. Getting Started & Commands

### Prerequisites
- Node.js `>= 20.x`

### Install Dependencies
```bash
npm install
```

### Start the Full-Stack Development Server (Port 3000)
Runs `server.ts` via `tsx`, mounting both the Express `/api/*` routes and Vite SPA middleware on `http://localhost:3000`:
```bash
npm run dev
```

### Run the Automated Unit Test Suite
Executes all 9 unit tests in `src/engine/chessSteg.test.ts` using Node's native test runner:
```bash
npx tsx --test src/engine/chessSteg.test.ts
```

### Type-Check & Build for Production
```bash
npm run lint
npm run build
```

---

## 6. REST API Reference

### `POST /api/encode`
Encodes a UTF-8 plaintext string into a steganographic PGN and returns the full ply-by-ply review ledger.

- **Request Body:**
  ```json
  {
    "text": "Hello ChessSteg",
    "passphrase": ""
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "pgn": "1. d4 Nf6 2. Nc3 d5 ... *",
    "total_bits": 152,
    "seed_hex": "1E6A",
    "length_bytes": 15,
    "seed_bits": "0001111001101010",
    "length_bits": "1011010011001011",
    "payload_bits": "...",
    "bitstream": "...",
    "total_plies": 76,
    "game_count": 1,
    "frames": [
      {
        "ply": 1,
        "move_number": 1,
        "turn": "W",
        "game_index": 1,
        "san": "d4",
        "uci": "d2d4",
        "from_sq": "d2",
        "to_sq": "d4",
        "bits": "00",
        "bit_offset": 0,
        "candidate_count": 4,
        "candidates": [
          { "index": 0, "bits": "00", "san": "d4", "uci": "d2d4", "score": 76, "selected": true },
          { "index": 1, "bits": "01", "san": "e4", "uci": "e2e4", "score": 76, "selected": false },
          { "index": 2, "bits": "10", "san": "Nc3", "uci": "b1c3", "score": 70, "selected": false },
          { "index": 3, "bits": "11", "san": "Nf3", "uci": "g1f3", "score": 70, "selected": false }
        ],
        "board": [["r","n","b","q","k","b","n","r"], ...]
      }
    ]
  }
  ```

### `POST /api/decode`
Extracts the hidden bitstream from a single-game or multi-game PGN, verifies the 16-bit seed checksum, and returns the decoded UTF-8 message alongside the ply-by-ply review ledger.

- **Request Body:**
  ```json
  {
    "pgn": "1. d4 Nf6 2. Nc3 d5 ... *",
    "passphrase": ""
  }
  ```
- **Response (`200 OK`):** Returns `DecodeResult` (`text`, `seed_hex`, `length_bytes`, `total_bits`, `total_plies`, `game_count`, `frames`).

### `POST /api/avalanche`
Encodes two messages (`text_a` and `text_b`) and computes their bit-level Hamming distance percentage, first divergent ply, and move-by-move comparison.

- **Request Body:**
  ```json
  {
    "text_a": "Launch sequence authorized at 04:00Z.",
    "text_b": "Launch sequence authorized at 04:00Z!",
    "passphrase": ""
  }
  ```
- **Response (`200 OK`):** Returns `AvalancheResult` (`a`, `b`, `differing_bits`, `hamming_pct`, `first_divergent_ply`, `ply_comparison`).

---

## 7. Automated Test Suite

`src/engine/chessSteg.test.ts` verifies 9 core invariants:

1. **Length Header Masking & Seed Checksum:** Confirms two messages of identical byte length produce distinct scrambled length headers (`Bits 16..31`) and round-trip cleanly.
2. **Passphrase Binding & Tamper Rejection:** Confirms passphrase-protected PGNs decode with the matching passphrase and throw an integrity/length error when given an incorrect passphrase.
3. **1-Character Avalanche Divergence:** Confirms changing the final character of a message alters the 16-bit seed, flips $>30\%$ of bits, and diverges at Ply 1.
4. **Move 1 Classical Opening Ordering:** Confirms White's Move 1 Top-4 candidate pool is `['d4', 'e4', 'Nc3', 'Nf3']` in exact order and excludes `Na3` and `f4`.
5. **Queen Blunder Prevention:** Confirms `Qxd5` capturing a defended pawn is heavily penalized ($< -5000$).
6. **Threatened-Piece Rescue Bonus:** Confirms an attacked Knight on `f3` receives a strong positive rescue score ($> +600$) to move to a safe square.
7. **Robust PGN Parser:** Confirms PGNs containing `[Event "..."]` headers, `{...}` comments, mid-game blank lines (`\n\n`), and `*` decode accurately.
8. **80-Column PGN Formatting, Result Tokens & Trailing Lichess Moves:** Confirms every game ends with a valid result token (`1-0`, `0-1`, `1/2-1/2`, `*`), wraps lines at $\le 80$ characters, and ignores extra non-candidate legal moves appended after the payload completes.
9. **Underpromotion Filter & Premature Game-Over Avoidance:** Confirms Queen promotion (`a8=Q+`) ranks #1 while underpromotions (`=R`, `=B`, `=N`) are excluded from the Top-4 pool, and premature checkmate (`Qxf7#`) is avoided when non-terminal legal moves exist.
