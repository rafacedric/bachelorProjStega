import React, { useState, useEffect, useCallback } from 'react';
import { SkipBack, ChevronLeft, ChevronRight, SkipForward, Play, Pause } from 'lucide-react';

interface CandidateMoveInfo {
  index: number;
  bits: string;
  san: string;
  uci: string;
  score: number;
  selected: boolean;
}

interface PlyFrame {
  ply: number;
  move_number: number;
  turn: 'W' | 'B';
  game_index: number;
  san: string;
  uci: string;
  bits: string;
  candidate_count: number;
  candidates: CandidateMoveInfo[];
  board: string[][];
}

interface StegData {
  pgn?: string;
  text?: string;
  total_bits: number;
  seed_hex: string;
  total_plies: number;
  game_count: number;
  frames: PlyFrame[];
}

const PIECE_UNICODE: Record<string, string> = {
  K: '♔', Q: '♕', R: '♖', B: '♗', N: '♘', P: '♙',
  k: '♚', q: '♛', r: '♜', b: '♝', n: '♞', p: '♟',
};

const START_BOARD = [
  ['r', 'n', 'b', 'q', 'k', 'b', 'n', 'r'],
  ['p', 'p', 'p', 'p', 'p', 'p', 'p', 'p'],
  ['.', '.', '.', '.', '.', '.', '.', '.'],
  ['.', '.', '.', '.', '.', '.', '.', '.'],
  ['.', '.', '.', '.', '.', '.', '.', '.'],
  ['.', '.', '.', '.', '.', '.', '.', '.'],
  ['P', 'P', 'P', 'P', 'P', 'P', 'P', 'P'],
  ['R', 'N', 'B', 'Q', 'K', 'B', 'N', 'R'],
];

export default function App() {
  const [textInput, setTextInput] = useState('Hello ChessSteg');
  const [passphrase, setPassphrase] = useState('');
  const [pgnInput, setPgnInput] = useState('');
  const [decodedText, setDecodedText] = useState('');
  const [data, setData] = useState<StegData | null>(null);
  const [ply, setPly] = useState(0);
  const [autoplay, setAutoplay] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  const encode = useCallback(async (text: string, key: string = '') => {
    if (!text.trim()) {
      setError('Enter text to encode.');
      return;
    }
    setError('');
    setAutoplay(false);
    const res = await fetch('/api/encode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, passphrase: key }),
    });
    const json = await res.json();
    if (!res.ok) {
      setError(json.detail || 'Encode error');
      return;
    }
    setData(json);
    setPgnInput(json.pgn || '');
    setDecodedText(text);
    setPly(json.total_plies > 0 ? 1 : 0);
  }, []);

  const decode = useCallback(async (pgn: string, key: string = '') => {
    if (!pgn.trim()) {
      setError('Enter PGN to decode.');
      return;
    }
    setError('');
    setAutoplay(false);
    const res = await fetch('/api/decode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pgn, passphrase: key }),
    });
    const json = await res.json();
    if (!res.ok) {
      setError(json.detail || 'Decode error');
      return;
    }
    setData(json);
    setDecodedText(json.text || '');
    setPly(json.total_plies > 0 ? 1 : 0);
  }, []);

  useEffect(() => {
    encode('Hello ChessSteg', '');
  }, [encode]);

  useEffect(() => {
    if (!autoplay || !data) return;
    const id = window.setInterval(() => {
      setPly((p) => {
        if (p >= data.total_plies) {
          setAutoplay(false);
          return p;
        }
        return p + 1;
      });
    }, 500);
    return () => clearInterval(id);
  }, [autoplay, data]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || !data) return;
      if (e.key === 'ArrowLeft') setPly((p) => Math.max(0, p - 1));
      if (e.key === 'ArrowRight') setPly((p) => Math.min(data.total_plies, p + 1));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [data]);

  const totalPlies = data?.total_plies ?? 0;
  const frame: PlyFrame = data?.frames[ply] ?? {
    ply: 0,
    move_number: 0,
    turn: 'W',
    game_index: 1,
    san: 'START',
    uci: '—',
    bits: '—',
    candidate_count: 0,
    candidates: [],
    board: START_BOARD,
  };

  return (
    <main className="p-4 font-mono text-sm text-black bg-white max-w-5xl mx-auto space-y-4">
      {error && <div role="alert" className="text-red-600">{error}</div>}

      {/* Encode / Decode Inputs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            encode(textInput, passphrase);
          }}
          className="space-y-2"
        >
          <label htmlFor="text-in" className="block font-bold">Plaintext to PGN</label>
          <textarea
            id="text-in"
            rows={2}
            value={textInput}
            onChange={(e) => setTextInput(e.target.value)}
            className="w-full border border-black p-1.5"
          />
          <div className="flex items-center gap-2">
            <input
              type="text"
              aria-label="Optional Passphrase"
              placeholder="Optional passphrase..."
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              className="border border-black px-2 py-1 text-xs flex-1"
            />
            <button type="submit" className="border border-black px-3 py-1 cursor-pointer">
              Encode
            </button>
          </div>
        </form>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            decode(pgnInput, passphrase);
          }}
          className="space-y-2"
        >
          <label htmlFor="pgn-in" className="block font-bold">PGN to Plaintext</label>
          <textarea
            id="pgn-in"
            rows={2}
            value={pgnInput}
            onChange={(e) => setPgnInput(e.target.value)}
            className="w-full border border-black p-1.5"
          />
          <div className="flex items-center gap-2">
            <button type="submit" className="border border-black px-3 py-1 cursor-pointer">
              Decode
            </button>
            <button
              type="button"
              onClick={() => {
                if (!pgnInput) return;
                navigator.clipboard.writeText(pgnInput);
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              }}
              className="border border-black px-3 py-1 cursor-pointer"
            >
              {copied ? '[ COPIED ]' : '[ COPY PGN ]'}
            </button>
            <span>Decoded: <strong data-testid="decoded-output">{decodedText}</strong></span>
          </div>
        </form>
      </div>

      {/* Board + Move & Bitstream Table */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-start">
        <div className="w-80">
          <div
            className="grid grid-cols-8 grid-rows-8 border border-black w-80 h-80 select-none"
            data-testid="chessboard-grid"
          >
            {frame.board.map((row, r) =>
              row.map((cell, c) => (
                <div
                  key={`${r}-${c}`}
                  className={`w-full h-full flex items-center justify-center text-2xl leading-none ${
                    (r + c) % 2 === 0 ? 'bg-white' : 'bg-gray-200'
                  }`}
                >
                  {PIECE_UNICODE[cell] || ''}
                </div>
              ))
            )}
          </div>

          <div className="grid grid-cols-5 gap-1 mt-2 w-80 text-xs">
            <button
              type="button"
              onClick={() => {
                setAutoplay(false);
                setPly(0);
              }}
              className="border border-black py-1.5 flex items-center justify-center gap-1 cursor-pointer hover:bg-gray-100"
            >
              <SkipBack className="w-3.5 h-3.5 shrink-0" />
              <span>START</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setAutoplay(false);
                setPly((p) => Math.max(0, p - 1));
              }}
              className="border border-black py-1.5 flex items-center justify-center gap-1 cursor-pointer hover:bg-gray-100"
            >
              <ChevronLeft className="w-3.5 h-3.5 shrink-0" />
              <span>PREV</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setAutoplay(false);
                setPly((p) => Math.min(totalPlies, p + 1));
              }}
              className="border border-black py-1.5 flex items-center justify-center gap-1 cursor-pointer hover:bg-gray-100"
            >
              <span>NEXT</span>
              <ChevronRight className="w-3.5 h-3.5 shrink-0" />
            </button>
            <button
              type="button"
              onClick={() => {
                setAutoplay(false);
                setPly(totalPlies);
              }}
              className="border border-black py-1.5 flex items-center justify-center gap-1 cursor-pointer hover:bg-gray-100"
            >
              <span>END</span>
              <SkipForward className="w-3.5 h-3.5 shrink-0" />
            </button>
            <button
              type="button"
              onClick={() => {
                if (ply >= totalPlies) setPly(0);
                setAutoplay((a) => !a);
              }}
              className="border border-black py-1.5 flex items-center justify-center gap-1 cursor-pointer hover:bg-gray-100"
            >
              {autoplay ? (
                <>
                  <Pause className="w-3.5 h-3.5 shrink-0" />
                  <span>STOP</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 shrink-0" />
                  <span>PLAY</span>
                </>
              )}
            </button>
          </div>

          {frame.candidates && frame.candidates.length > 0 && (
            <div className="grid grid-cols-4 gap-1 mt-2 w-80 text-[11px]" data-testid="candidate-pool">
              {frame.candidates.map((c) => (
                <div
                  key={c.uci}
                  className={`border border-black p-1 text-center ${
                    c.selected ? 'bg-[#D9381E] text-white font-bold' : ''
                  }`}
                >
                  <div>{c.bits}: {c.san}</div>
                  <div>({c.score >= 0 ? `+${c.score}` : c.score})</div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="border border-black max-h-[380px] overflow-y-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-black">
                <th className="p-1">Ply</th>
                <th className="p-1">Game</th>
                <th className="p-1">Move</th>
                <th className="p-1">SAN</th>
                <th className="p-1">UCI</th>
                <th className="p-1">Bits</th>
                <th className="p-1">Pool</th>
              </tr>
            </thead>
            <tbody>
              {data?.frames.map((p, idx) => {
                const showNewGameRow =
                  idx > 0 && p.game_index > data.frames[idx - 1].game_index;
                return (
                  <React.Fragment key={p.ply}>
                    {showNewGameRow && (
                      <tr className="border-b border-black bg-gray-100 font-bold">
                        <td colSpan={7} className="p-1">
                          {`// GAME 0${p.game_index} — NEW BOARD INITIALIZED`}
                        </td>
                      </tr>
                    )}
                    <tr
                      onClick={() => setPly(p.ply)}
                      className={`cursor-pointer border-b border-gray-200 ${
                        p.ply === ply ? 'bg-[#D9381E] text-white font-bold' : ''
                      }`}
                    >
                      <td className="p-1">{p.ply}</td>
                      <td className="p-1">{p.ply === 0 ? '—' : p.game_index}</td>
                      <td className="p-1">{p.ply === 0 ? '—' : `${p.move_number}${p.turn === 'W' ? '.' : '...'}`}</td>
                      <td className="p-1">{p.san}</td>
                      <td className="p-1">{p.uci}</td>
                      <td className="p-1">{p.bits}</td>
                      <td className="p-1">{p.candidate_count}</td>
                    </tr>
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}
