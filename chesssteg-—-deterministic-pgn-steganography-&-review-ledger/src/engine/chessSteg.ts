import crypto from 'node:crypto';
import { Chess, Move, Square } from 'chess.js';

export interface CandidateMoveInfo {
  index: number;
  bits: string;
  san: string;
  uci: string;
  score: number;
  selected: boolean;
}

export interface PlyFrame {
  ply: number;
  move_number: number;
  turn: 'W' | 'B';
  game_index: number;
  san: string;
  uci: string;
  from_sq: string | null;
  to_sq: string | null;
  bits: string;
  bit_offset: number;
  candidate_count: number;
  candidates: CandidateMoveInfo[];
  board: string[][];
}

export interface EncodeResult {
  pgn: string;
  total_bits: number;
  seed_hex: string;
  length_bytes: number;
  seed_bits: string;
  length_bits: string;
  payload_bits: string;
  bitstream: string;
  total_plies: number;
  game_count: number;
  frames: PlyFrame[];
}

export interface DecodeResult {
  text: string;
  seed_hex: string;
  length_bytes: number;
  total_bits: number;
  seed_bits: string;
  length_bits: string;
  payload_bits: string;
  bitstream: string;
  total_plies: number;
  game_count: number;
  frames: PlyFrame[];
}

export interface AvalanchePlyDiff {
  ply: number;
  move_number: number;
  turn: 'W' | 'B';
  san_a: string;
  bits_a: string;
  san_b: string;
  bits_b: string;
  diverged: boolean;
}

export interface AvalancheResult {
  a: EncodeResult;
  b: EncodeResult;
  differing_bits: number;
  hamming_pct: number;
  first_divergent_ply: number | null;
  ply_comparison: AvalanchePlyDiff[];
}

// ---------------------------------------------------------------------------
// 1. REVERSIBLE AVALANCHE BITSTREAM PACKING (WITH LENGTH MASK & CHECKSUM)
// ---------------------------------------------------------------------------

export function encodeBitstream(
  text: string,
  passphrase: string = ''
): {
  bits: string;
  seed_hex: string;
  length_bytes: number;
  seed_bits: string;
  length_bits: string;
  payload_bits: string;
  scrambled_hex: string;
} {
  const raw = Buffer.from(text, 'utf-8');
  if (raw.length > 65535) {
    throw new Error('Payload exceeds maximum 65,535 byte limit.');
  }

  const keyMaterial = Buffer.from(passphrase, 'utf-8');

  // 16-bit seed bound to full message + optional passphrase
  const seed = crypto
    .createHash('sha256')
    .update(Buffer.concat([raw, keyMaterial]))
    .digest()
    .subarray(0, 2);

  // 16-bit big-endian length header scrambled with seed + passphrase
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

  // XOR-scramble payload bytes using seed + keyMaterial + 2-byte big-endian index
  const scrambled = Buffer.alloc(raw.length);
  for (let i = 0; i < raw.length; i++) {
    const idxBuf = Buffer.alloc(2);
    idxBuf.writeUInt16BE(i, 0);
    const maskByte = crypto
      .createHash('sha256')
      .update(Buffer.concat([seed, keyMaterial, idxBuf]))
      .digest()[0];
    scrambled[i] = raw[i] ^ maskByte;
  }

  const packet = Buffer.concat([seed, scrambledLen, scrambled]);

  const toBitString = (buf: Buffer): string =>
    Array.from(buf)
      .map((b) => b.toString(2).padStart(8, '0'))
      .join('');

  return {
    bits: toBitString(packet),
    seed_hex: seed.toString('hex').toUpperCase(),
    length_bytes: raw.length,
    seed_bits: toBitString(seed),
    length_bits: toBitString(scrambledLen),
    payload_bits: toBitString(scrambled),
    scrambled_hex: scrambled.toString('hex').toUpperCase(),
  };
}

export function decodeBitstream(
  bits: string,
  passphrase: string = ''
): {
  text: string;
  seed_hex: string;
  msg_len: number;
  total_bits: number;
  seed_bits: string;
  length_bits: string;
  payload_bits: string;
} {
  if (bits.length < 32) {
    throw new Error(
      'Bitstream too short to contain 32-bit header (16-bit seed + 16-bit length).'
    );
  }
  const seedBits = bits.slice(0, 16);
  const lenBits = bits.slice(16, 32);

  const seed = Buffer.from([
    parseInt(seedBits.slice(0, 8), 2),
    parseInt(seedBits.slice(8, 16), 2),
  ]);
  const scrambledLen = Buffer.from([
    parseInt(lenBits.slice(0, 8), 2),
    parseInt(lenBits.slice(8, 16), 2),
  ]);

  const keyMaterial = Buffer.from(passphrase, 'utf-8');

  // Unmask 16-bit payload byte length
  const lenMask = crypto
    .createHash('sha256')
    .update(Buffer.concat([seed, keyMaterial, Buffer.from('LEN')]))
    .digest()
    .subarray(0, 2);
  const lenBuf = Buffer.from([
    scrambledLen[0] ^ lenMask[0],
    scrambledLen[1] ^ lenMask[1],
  ]);
  const msgLen = lenBuf.readUInt16BE(0);
  const totalNeeded = 32 + msgLen * 8;

  if (bits.length < totalNeeded) {
    throw new Error(
      `Integrity or length check failed: Incorrect passphrase, tampered PGN moves, or truncated PGN (unmasked header requested ${msgLen} bytes / ${totalNeeded} bits, but PGN has ${bits.length} bits).`
    );
  }

  const payloadBits = bits.slice(32, totalNeeded);
  const scrambled = Buffer.alloc(msgLen);
  for (let i = 0; i < msgLen; i++) {
    scrambled[i] = parseInt(payloadBits.slice(i * 8, (i + 1) * 8), 2);
  }

  const raw = Buffer.alloc(msgLen);
  for (let i = 0; i < msgLen; i++) {
    const idxBuf = Buffer.alloc(2);
    idxBuf.writeUInt16BE(i, 0);
    const maskByte = crypto
      .createHash('sha256')
      .update(Buffer.concat([seed, keyMaterial, idxBuf]))
      .digest()[0];
    raw[i] = scrambled[i] ^ maskByte;
  }

  // Strict 16-bit seed checksum verification
  const expectedSeed = crypto
    .createHash('sha256')
    .update(Buffer.concat([raw, keyMaterial]))
    .digest()
    .subarray(0, 2);

  if (!expectedSeed.equals(seed)) {
    throw new Error(
      'Integrity check failed: PGN moves were altered or passphrase is incorrect.'
    );
  }

  return {
    text: raw.toString('utf-8'),
    seed_hex: seed.toString('hex').toUpperCase(),
    msg_len: msgLen,
    total_bits: totalNeeded,
    seed_bits: seedBits,
    length_bits: lenBits,
    payload_bits: payloadBits,
  };
}

// ---------------------------------------------------------------------------
// 2. DETERMINISTIC LIGHTWEIGHT MOVE SCORER (NO STOCKFISH BINARY)
// ---------------------------------------------------------------------------

const PIECE_VALUES: Record<string, number> = {
  p: 100,
  n: 320,
  b: 330,
  r: 500,
  q: 900,
  k: 20000,
};

const INNER_CENTER = new Set(['d4', 'd5', 'e4', 'e5']);
const OUTER_CENTER = new Set(['c4', 'c5', 'd3', 'd6', 'e3', 'e6']);
const CENTRAL_FILES = new Set(['c', 'd', 'e', 'f']);
const BG_FILES = new Set(['b', 'g']);

export function moveToUci(move: Move): string {
  return `${move.from}${move.to}${move.promotion ? move.promotion : ''}`;
}

export function getPositionFenKey(board: Chess): string {
  return board.fen().split(' ').slice(0, 2).join(' ');
}

export function scoreMove(
  board: Chess,
  move: Move,
  recentFens: Set<string> = new Set()
): number {
  let score = 0;
  const attackerVal = PIECE_VALUES[move.piece] ?? 100;

  // 1. Capture value (MVV-LVA heuristic)
  if (move.captured) {
    const victimVal = PIECE_VALUES[move.captured] ?? 100;
    score += victimVal * 10 - Math.floor(attackerVal / 10);
  }

  // 2. Promotion bonus (only Queen promotion gets +900; penalize underpromotions by -1000)
  if (move.promotion) {
    if (move.promotion === 'q') {
      score += PIECE_VALUES.q;
    } else {
      score -= 1000;
    }
  }

  // 3. Center-square bonus (d4, d5, e4, e5 = +45; c4, c5, d3, d6, e3, e6 = +25)
  if (INNER_CENTER.has(move.to)) {
    score += 45;
  } else if (OUTER_CENTER.has(move.to)) {
    score += 25;
  }

  // 4. Piece development, file centrality, rescue bonus & castling bonus
  const fromRank = parseInt(move.from[1], 10) - 1;
  const toRank = parseInt(move.to[1], 10) - 1;
  const toFile = move.to[0];
  const fromFile = move.from[0];
  const isWhite = board.turn() === 'w';
  const homeRank = isWhite ? 0 : 7;
  const fullMoveNumber = board.moveNumber();
  const opponentPre = isWhite ? 'b' : 'w';
  const isFromAttacked = board.isAttacked(move.from as Square, opponentPre);

  if (isFromAttacked) {
    score += Math.floor(attackerVal * 2);
  }

  if (move.piece === 'n' || move.piece === 'b') {
    if (fromRank === homeRank && toRank !== homeRank) {
      score += 50;
    }
    const allowCentralityBonus =
      fullMoveNumber > 8 || fromRank === homeRank || Boolean(move.captured);
    if (CENTRAL_FILES.has(toFile)) {
      if (allowCentralityBonus) score += 20;
    } else if (BG_FILES.has(toFile)) {
      if (allowCentralityBonus) score += 5;
    } else {
      score -= 30;
    }
    if (
      fullMoveNumber <= 8 &&
      fromRank !== homeRank &&
      !move.captured &&
      !isFromAttacked
    ) {
      score -= 30;
    }
  } else if (move.piece === 'p') {
    const advance = isWhite ? toRank - fromRank : fromRank - toRank;
    score += advance * 8;
    const uci = `${move.from}${move.to}`;
    if (
      uci === 'd2d4' ||
      uci === 'e2e4' ||
      uci === 'd7d5' ||
      uci === 'e7e5'
    ) {
      score += 15;
    }
    if (fullMoveNumber <= 10 && !move.captured) {
      if (move.from === 'f2' || move.from === 'f7') {
        score -= 25;
      } else if (fromFile === 'a' || fromFile === 'h') {
        score -= 20;
      }
    }
  }

  const isCastling = move.isKingsideCastle() || move.isQueensideCastle();
  if (fullMoveNumber <= 10) {
    if (move.piece === 'q' && fromRank === homeRank) {
      score -= 40;
    } else if (move.piece === 'k' && !isCastling) {
      score -= 60;
    }
  }

  if (isCastling) {
    score += 75;
  }

  // 5. Check bonus
  if (move.san.includes('+') || move.san.includes('#')) {
    score += 30;
  }

  // 6. Simulate move on board to evaluate post-move destination safety, game-over avoidance & repetition
  board.move(move);
  if (board.isGameOver()) {
    score -= 50000;
  }
  const resultingFenKey = getPositionFenKey(board);
  if (recentFens.has(resultingFenKey)) {
    score -= 600;
  }

  // Side to move after pushing is the opponent
  const opponentColor = board.turn();
  if (board.isAttacked(move.to as Square, opponentColor)) {
    score -= attackerVal * 9;
  }
  board.undo();

  return score;
}

export function getCandidateMoves(
  board: Chess,
  recentFens: Set<string> = new Set()
): {
  move: Move;
  uci: string;
  score: number;
}[] {
  const legalMoves = board.moves({ verbose: true });
  if (legalMoves.length === 0) return [];

  const scored = legalMoves
    .map((m) => ({
      move: m,
      uci: moveToUci(m),
      score: scoreMove(board, m, recentFens),
    }))
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return a.uci.localeCompare(b.uci);
    });

  if (scored.length >= 4) {
    return scored.slice(0, 4);
  } else if (scored.length >= 2) {
    return scored.slice(0, 2);
  } else {
    return [scored[0]];
  }
}

export function boardToMatrix(board: Chess): string[][] {
  const rawBoard = board.board();
  return rawBoard.map((row) =>
    row.map((cell) => {
      if (!cell) return '.';
      return cell.color === 'w'
        ? cell.type.toUpperCase()
        : cell.type.toLowerCase();
    })
  );
}

function getGameResultToken(board: Chess): '1-0' | '0-1' | '1/2-1/2' | '*' {
  if (board.isCheckmate()) {
    return board.turn() === 'b' ? '1-0' : '0-1';
  }
  if (
    board.isDraw() ||
    board.isStalemate() ||
    board.isThreefoldRepetition() ||
    board.isInsufficientMaterial()
  ) {
    return '1/2-1/2';
  }
  return '*';
}

function formatGameMovesToPgn(
  sans: string[],
  resultToken: '1-0' | '0-1' | '1/2-1/2' | '*' = '*'
): string {
  const tokens: string[] = [];
  for (let i = 0; i < sans.length; i++) {
    if (i % 2 === 0) {
      tokens.push(`${Math.floor(i / 2) + 1}. ${sans[i]}`);
    } else {
      tokens.push(sans[i]);
    }
  }
  tokens.push(resultToken);

  const lines: string[] = [];
  let currentLine = '';
  for (const token of tokens) {
    if (!currentLine) {
      currentLine = token;
    } else if (currentLine.length + 1 + token.length <= 80) {
      currentLine += ` ${token}`;
    } else {
      lines.push(currentLine);
      currentLine = token;
    }
  }
  if (currentLine) {
    lines.push(currentLine);
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// 3. ENCODE / DECODE ENGINE
// ---------------------------------------------------------------------------

export function runEncode(
  text: string,
  passphrase: string = ''
): EncodeResult {
  if (!text || text.length === 0) {
    throw new Error('Secret text message cannot be empty.');
  }

  const pack = encodeBitstream(text, passphrase);
  const bitstream = pack.bits;
  const totalBits = bitstream.length;

  let bitCursor = 0;
  let plyCounter = 0;
  let gameIndex = 1;
  const pgnGames: string[] = [];

  const initialBoard = new Chess();
  const frames: PlyFrame[] = [
    {
      ply: 0,
      move_number: 0,
      turn: 'W',
      game_index: 1,
      san: 'START',
      uci: '—',
      from_sq: null,
      to_sq: null,
      bits: '—',
      bit_offset: 0,
      candidate_count: getCandidateMoves(initialBoard).length,
      candidates: [],
      board: boardToMatrix(initialBoard),
    },
  ];

  while (bitCursor < totalBits) {
    const board = new Chess();
    const recentFens = new Set<string>([getPositionFenKey(board)]);
    const gameSans: string[] = [];

    while (!board.isGameOver() && bitCursor < totalBits) {
      const candidates = getCandidateMoves(board, recentFens);
      const bitsToRead =
        candidates.length >= 4 ? 2 : candidates.length >= 2 ? 1 : 0;

      const bitOffset = bitCursor;
      let chunk = '—';
      let chosenIdx = 0;

      if (bitsToRead > 0) {
        chunk = bitstream.slice(bitCursor, bitCursor + bitsToRead);
        if (chunk.length < bitsToRead) {
          chunk = chunk.padEnd(bitsToRead, '0');
        }
        chosenIdx = parseInt(chunk, 2);
        bitCursor += bitsToRead;
      }

      const chosen = candidates[chosenIdx];
      const moveNumber = board.moveNumber();
      const turnStr: 'W' | 'B' = board.turn() === 'w' ? 'W' : 'B';

      const candDetails: CandidateMoveInfo[] = candidates.map((c, idx) => ({
        index: idx,
        bits: bitsToRead > 0 ? idx.toString(2).padStart(bitsToRead, '0') : '—',
        san: c.move.san,
        uci: c.uci,
        score: c.score,
        selected: idx === chosenIdx,
      }));

      board.move(chosen.move);
      recentFens.add(getPositionFenKey(board));
      gameSans.push(chosen.move.san);
      plyCounter += 1;

      frames.push({
        ply: plyCounter,
        move_number: moveNumber,
        turn: turnStr,
        game_index: gameIndex,
        san: chosen.move.san,
        uci: chosen.uci,
        from_sq: chosen.move.from,
        to_sq: chosen.move.to,
        bits: chunk,
        bit_offset: bitOffset,
        candidate_count: candidates.length,
        candidates: candDetails,
        board: boardToMatrix(board),
      });
    }

    if (gameSans.length > 0) {
      const resultToken = getGameResultToken(board);
      pgnGames.push(formatGameMovesToPgn(gameSans, resultToken));
      gameIndex += 1;
    }
  }

  return {
    pgn: pgnGames.join('\n\n'),
    total_bits: totalBits,
    seed_hex: pack.seed_hex,
    length_bytes: pack.length_bytes,
    seed_bits: pack.seed_bits,
    length_bits: pack.length_bits,
    payload_bits: pack.payload_bits,
    bitstream,
    total_plies: plyCounter,
    game_count: pgnGames.length,
    frames,
  };
}

export function splitPgnIntoMoveLists(pgnInput: string): string[][] {
  // 1. Strip PGN header tags [Event "..."], block comments {...}, and line comments ;...
  const stripped = pgnInput
    .replace(/\[[^\]]*\]/g, ' ')
    .replace(/\{[^}]*\}/g, ' ')
    .replace(/;[^\n]*/g, ' ')
    .trim();

  if (!stripped) return [];

  // 2. Split on explicit PGN termination markers (1-0, 0-1, 1/2-1/2, *) or a new "1. " move number
  // that follows at least one prior move, so accidental blank lines mid-game never split a game.
  const gameChunks = stripped
    .split(/(?:(?:\b(?:1-0|0-1|1\/2-1\/2)\b|\*)(?:\s+|$)|\s+(?=1\.\s+[A-Za-z]))/g)
    .map((c) => c.trim())
    .filter(Boolean);

  const moveLists: string[][] = [];
  for (const chunk of gameChunks) {
    const cleaned = chunk
      .replace(/(?:\b(?:1-0|0-1|1\/2-1\/2)\b|\*)/g, ' ')
      .replace(/\d+\.(\.\.)?/g, ' ')
      .trim();
    if (cleaned) {
      const tokens = cleaned.split(/\s+/).filter(Boolean);
      if (tokens.length > 0) {
        moveLists.push(tokens);
      }
    }
  }

  return moveLists;
}

function unmaskHeaderTotalBits(
  headerBits: string,
  passphrase: string
): number {
  const seed = Buffer.from([
    parseInt(headerBits.slice(0, 8), 2),
    parseInt(headerBits.slice(8, 16), 2),
  ]);
  const scrambledLen = Buffer.from([
    parseInt(headerBits.slice(16, 24), 2),
    parseInt(headerBits.slice(24, 32), 2),
  ]);
  const keyMaterial = Buffer.from(passphrase, 'utf-8');
  const lenMask = crypto
    .createHash('sha256')
    .update(Buffer.concat([seed, keyMaterial, Buffer.from('LEN')]))
    .digest()
    .subarray(0, 2);
  const lenBuf = Buffer.from([
    scrambledLen[0] ^ lenMask[0],
    scrambledLen[1] ^ lenMask[1],
  ]);
  const msgLen = lenBuf.readUInt16BE(0);
  return 32 + msgLen * 8;
}

export function runDecode(
  pgnInput: string,
  passphrase: string = ''
): DecodeResult {
  if (!pgnInput || !pgnInput.trim()) {
    throw new Error('PGN input cannot be empty.');
  }

  const moveLists = splitPgnIntoMoveLists(pgnInput);
  if (moveLists.length === 0) {
    throw new Error('No valid chess moves found in PGN input.');
  }

  const extractedBits: string[] = [];
  let plyCounter = 0;
  let totalBitsExtracted = 0;
  let headerTotalNeeded: number | null = null;
  let payloadComplete = false;
  let payloadValidationAttempted = false;

  const initialBoard = new Chess();
  const frames: PlyFrame[] = [
    {
      ply: 0,
      move_number: 0,
      turn: 'W',
      game_index: 1,
      san: 'START',
      uci: '—',
      from_sq: null,
      to_sq: null,
      bits: '—',
      bit_offset: 0,
      candidate_count: getCandidateMoves(initialBoard).length,
      candidates: [],
      board: boardToMatrix(initialBoard),
    },
  ];

  moveLists.forEach((tokens, gIdx) => {
    const board = new Chess();
    const recentFens = new Set<string>([getPositionFenKey(board)]);
    const gameIndex = gIdx + 1;

    for (const sanToken of tokens) {
      const candidates = getCandidateMoves(board, recentFens);
      const bitsToRead =
        candidates.length >= 4 ? 2 : candidates.length >= 2 ? 1 : 0;

      const moveNumber = board.moveNumber();
      const turnStr: 'W' | 'B' = board.turn() === 'w' ? 'W' : 'B';

      let playedMove: Move;
      try {
        playedMove = board.move(sanToken);
      } catch {
        throw new Error(
          `Illegal or unparseable move "${sanToken}" at ply ${plyCounter + 1}.`
        );
      }

      const playedUci = moveToUci(playedMove);
      const chosenIdx = candidates.findIndex((c) => c.uci === playedUci);
      if (chosenIdx === -1 && !payloadComplete) {
        throw new Error(
          `Move ${playedMove.san} (${playedUci}) at ply ${plyCounter + 1} is not in the deterministic top-${candidates.length} candidate pool.`
        );
      }

      recentFens.add(getPositionFenKey(board));

      const bitOffset = totalBitsExtracted;
      let chunk = '—';
      if (!payloadComplete && bitsToRead > 0 && chosenIdx !== -1) {
        chunk = chosenIdx.toString(2).padStart(bitsToRead, '0');
        extractedBits.push(chunk);
        totalBitsExtracted += bitsToRead;

        if (headerTotalNeeded === null && totalBitsExtracted >= 32) {
          headerTotalNeeded = unmaskHeaderTotalBits(
            extractedBits.join('').slice(0, 32),
            passphrase
          );
        }

        if (
          !payloadValidationAttempted &&
          headerTotalNeeded !== null &&
          totalBitsExtracted >= headerTotalNeeded
        ) {
          payloadValidationAttempted = true;
          try {
            decodeBitstream(
              extractedBits.join('').slice(0, headerTotalNeeded),
              passphrase
            );
            payloadComplete = true;
          } catch {
            payloadComplete = false;
          }
        }
      }

      const candDetails: CandidateMoveInfo[] = candidates.map((c, idx) => ({
        index: idx,
        bits: bitsToRead > 0 ? idx.toString(2).padStart(bitsToRead, '0') : '—',
        san: c.move.san,
        uci: c.uci,
        score: c.score,
        selected: idx === chosenIdx,
      }));

      plyCounter += 1;
      frames.push({
        ply: plyCounter,
        move_number: moveNumber,
        turn: turnStr,
        game_index: gameIndex,
        san: playedMove.san,
        uci: playedUci,
        from_sq: playedMove.from,
        to_sq: playedMove.to,
        bits: chunk,
        bit_offset: bitOffset,
        candidate_count: candidates.length,
        candidates: candDetails,
        board: boardToMatrix(board),
      });
    }
  });

  const fullBitstream = extractedBits.join('');
  const decoded = decodeBitstream(fullBitstream, passphrase);

  return {
    text: decoded.text,
    seed_hex: decoded.seed_hex,
    length_bytes: decoded.msg_len,
    total_bits: decoded.total_bits,
    seed_bits: decoded.seed_bits,
    length_bits: decoded.length_bits,
    payload_bits: decoded.payload_bits,
    bitstream: fullBitstream.slice(0, decoded.total_bits),
    total_plies: plyCounter,
    game_count: moveLists.length,
    frames,
  };
}

export function runAvalanche(
  textA: string,
  textB: string,
  passphrase: string = ''
): AvalancheResult {
  const resA = runEncode(textA, passphrase);
  const resB = runEncode(textB, passphrase);

  const bitsA = resA.bitstream;
  const bitsB = resB.bitstream;
  const minLen = Math.min(bitsA.length, bitsB.length);
  let differingBits = Math.abs(bitsA.length - bitsB.length);
  for (let i = 0; i < minLen; i++) {
    if (bitsA[i] !== bitsB[i]) differingBits++;
  }
  const maxLen = Math.max(bitsA.length, bitsB.length, 1);
  const hammingPct = Number(((differingBits / maxLen) * 100).toFixed(1));

  let firstDivergentPly: number | null = null;
  const maxPlies = Math.min(resA.frames.length, resB.frames.length);
  const plyComparison: AvalanchePlyDiff[] = [];

  for (let p = 1; p < Math.min(maxPlies, 25); p++) {
    const fa = resA.frames[p];
    const fb = resB.frames[p];
    const sameMove = fa.uci === fb.uci;
    if (!sameMove && firstDivergentPly === null) {
      firstDivergentPly = p;
    }
    plyComparison.push({
      ply: p,
      move_number: fa.move_number,
      turn: fa.turn,
      san_a: fa.san,
      bits_a: fa.bits,
      san_b: fb.san,
      bits_b: fb.bits,
      diverged: !sameMove,
    });
  }

  return {
    a: resA,
    b: resB,
    differing_bits: differingBits,
    hamming_pct: hammingPct,
    first_divergent_ply: firstDivergentPly,
    ply_comparison: plyComparison,
  };
}
