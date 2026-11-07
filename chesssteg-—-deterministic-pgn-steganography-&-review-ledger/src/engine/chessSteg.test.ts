import test from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeBitstream,
  decodeBitstream,
  runEncode,
  runDecode,
  runAvalanche,
  getCandidateMoves,
  scoreMove,
} from './chessSteg';
import { Chess } from 'chess.js';

test('bitstream packing scrambles length header and verifies 16-bit seed checksum', () => {
  const secretA = 'Alpha-Bravo-01';
  const secretB = 'Alpha-Bravo-02'; // Identical byte length (14 bytes)

  const packedA = encodeBitstream(secretA);
  const packedB = encodeBitstream(secretB);

  // Length header (bits 16..31) is masked by seed, so two same-length messages do NOT share identical length_bits
  assert.notEqual(packedA.length_bits, packedB.length_bits);

  const unpackedA = decodeBitstream(packedA.bits);
  assert.equal(unpackedA.text, secretA);
  assert.equal(unpackedA.seed_hex, packedA.seed_hex);
});

test('passphrase-bound steganography and checksum tamper rejection', () => {
  const secret = 'Top secret launch code 9941';
  const encoded = runEncode(secret, 'my-secret-passphrase');

  // Decoding with correct passphrase succeeds
  const decoded = runDecode(encoded.pgn, 'my-secret-passphrase');
  assert.equal(decoded.text, secret);

  // Decoding with wrong passphrase fails integrity/length check
  assert.throws(
    () => runDecode(encoded.pgn, 'wrong-passphrase'),
    /Integrity( or length)? check failed/
  );
});

test('avalanche effect: 1-character change at end alters 16-bit seed and diverges at Ply 1', () => {
  const msgA = 'Launch sequence authorized at 04:00Z.';
  const msgB = 'Launch sequence authorized at 04:00Z!';

  const diff = runAvalanche(msgA, msgB);

  assert.notEqual(diff.a.seed_hex, diff.b.seed_hex);
  assert.ok(diff.hamming_pct > 30, `Expected high bit avalanche, got ${diff.hamming_pct}%`);
  assert.equal(diff.first_divergent_ply, 1, 'Expected game divergence starting at Ply 1');
  assert.notEqual(diff.a.frames[1].san, diff.b.frames[1].san);
});

test('chess heuristics: central pawns (d4/e4) and central knights (Nc3/Nf3) rank #1-#4 on Move 1', () => {
  const board = new Chess();
  const candidates = getCandidateMoves(board);

  assert.equal(candidates.length, 4);
  const topSans = candidates.map((c) => c.move.san);

  // Top 4 opening moves must be ['d4', 'e4', 'Nc3', 'Nf3'] in exact order, never Na3 or f4
  assert.ok(!topSans.includes('Na3'), 'Rim knight Na3 should not be in top 4 opening moves');
  assert.ok(!topSans.includes('f4'), 'Early f4 should not be in top 4 opening moves');
  assert.deepEqual(topSans, ['d4', 'e4', 'Nc3', 'Nf3']);
});

test('chess heuristics: Queen does not blunder into a defended pawn', () => {
  // Position where White Queen on d4 can capture a Black pawn on d5 defended by e6 pawn
  const board = new Chess('rnbqkbnr/ppp2ppp/4p3/3p4/3Q4/8/PPP1PPPP/RNB1KBNR w KQkq - 0 3');
  const moves = board.moves({ verbose: true });
  const qxd5 = moves.find((m) => m.san === 'Qxd5');
  assert.ok(qxd5, 'Expected Qxd5 to be a legal move');

  const qxd5Score = scoreMove(board, qxd5!);
  assert.ok(
    qxd5Score < -5000,
    `Expected Queen capture of defended pawn to be heavily penalized, got ${qxd5Score}`
  );
});

test('chess heuristics: threatened high-value piece receives rescue bonus to move to a safe square', () => {
  // White Knight on f3 is attacked by Black pawn on e4 (after 1. Nf3 d5 2. d4 e4)
  const board = new Chess('rnbqkbnr/ppp2ppp/8/3p4/3Pp3/5N2/PPP1PPPP/RNBQKB1R w KQkq - 0 3');
  const moves = board.moves({ verbose: true });
  const nfd2 = moves.find((m) => m.san === 'Nfd2');
  const c4 = moves.find((m) => m.san === 'c4');
  assert.ok(nfd2 && c4, 'Expected Nfd2 and c4 to be legal moves');

  const rescueScore = scoreMove(board, nfd2!);
  const ignoreThreatScore = scoreMove(board, c4!);

  assert.ok(
    rescueScore > 600 && rescueScore > ignoreThreatScore,
    `Expected attacked Knight escape Nfd2 (${rescueScore}) to strongly outscore non-rescue move c4 (${ignoreThreatScore})`
  );
});

test('robust PGN splitting handles accidental mid-game blank lines, headers, and comments', () => {
  const message = 'Robust PGN parser test';
  const encoded = runEncode(message);

  // Strip trailing result token before injecting mid-game noise and re-appending *
  const withoutResult = encoded.pgn.replace(/\s+(?:1-0|0-1|1\/2-1\/2|\*)$/, '');
  const tokens = withoutResult.split(/\s+/);
  const mid = Math.floor(tokens.length / 2);
  const noisyPgn = `[Event "Casual Game"]\n[Site "Local"]\n\n${tokens
    .slice(0, mid)
    .join(' ')} {mid-game comment}\n\n${tokens.slice(mid).join(' ')} *`;

  const decoded = runDecode(noisyPgn);
  assert.equal(decoded.text, message);
});

test('PGN output includes standard result token, 80-column wrapping, and ignores trailing Lichess moves on decode', () => {
  const message = 'Lichess paste test';
  const encoded = runEncode(message);

  // 1. Every game ends with a valid PGN termination token (1-0, 0-1, 1/2-1/2, or *)
  assert.match(encoded.pgn.trim(), /(?:1-0|0-1|1\/2-1\/2|\*)$/);

  // 2. Every line in the generated PGN is wrapped at <= 80 characters
  for (const line of encoded.pgn.split('\n')) {
    assert.ok(
      line.length <= 80,
      `Expected PGN line length <= 80 chars, got ${line.length}: "${line}"`
    );
  }

  // 3. Reconstruct board at the end of the encoded game and play 2 extra non-candidate legal moves
  const moveLists = encoded.frames.slice(1).map((f) => f.san);
  const board = new Chess();
  for (const san of moveLists) {
    board.move(san);
  }

  const extraSans: string[] = [];
  for (let i = 0; i < 2 && !board.isGameOver(); i++) {
    const legal = board.moves({ verbose: true });
    // Pick the lowest-scored move (guaranteed outside top-4 candidate pool when >= 5 legal moves exist)
    const candidates = new Set(getCandidateMoves(board).map((c) => c.move.san));
    const nonCandidate = legal.find((m) => !candidates.has(m.san)) ?? legal[legal.length - 1];
    board.move(nonCandidate);
    extraSans.push(nonCandidate.san);
  }

  // Append those extra moves before the trailing * result token
  const baseMovetext = encoded.pgn.replace(/\s*\*\s*$/, '');
  const startPly = moveLists.length;
  const extraTokens = extraSans.map((san, idx) => {
    const plyIdx = startPly + idx;
    return plyIdx % 2 === 0 ? `${Math.floor(plyIdx / 2) + 1}. ${san}` : san;
  });
  const extendedPgn = `${baseMovetext} ${extraTokens.join(' ')} *`;

  const decoded = runDecode(extendedPgn);
  assert.equal(decoded.text, message);
  assert.equal(decoded.total_plies, encoded.total_plies + extraSans.length);
  assert.equal(decoded.frames[decoded.frames.length - 1].bits, '—');
});

test('chess heuristics: underpromotions (=R, =B, =N) are excluded from Top-4 pool and premature game-ending moves are penalized', () => {
  // White pawn on a7 can promote to Q, R, B, N, while other normal moves exist
  const promoBoard = new Chess('4k3/P7/8/8/8/8/4PPPP/4KBNR w K - 0 1');
  const candidates = getCandidateMoves(promoBoard);
  const topSans = candidates.map((c) => c.move.san);

  assert.equal(topSans[0], 'a8=Q+');
  assert.ok(!topSans.some((s) => s.includes('=R') || s.includes('=B') || s.includes('=N')), `Expected no underpromotions in Top-4 pool, got ${topSans.join(', ')}`);

  // Position where Qxf7# is checkmate in 1 (Scholar's Mate), verify non-terminal moves outscore Qxf7#
  const mateBoard = new Chess('r1bqkbnr/pppp1ppp/2n5/4p3/2B1P3/5Q2/PPPP1PPP/RNB1K1NR w KQkq - 4 3');
  const mateCandidates = getCandidateMoves(mateBoard);
  const mateSanList = mateCandidates.map((c) => c.move.san);
  assert.ok(!mateSanList.includes('Qxf7#'), 'Expected premature checkmate Qxf7# to be excluded from Top-4 when non-terminal moves exist');
});

