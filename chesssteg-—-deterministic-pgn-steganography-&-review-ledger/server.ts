import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer as createViteServer } from 'vite';
import { runEncode, runDecode, runAvalanche } from './src/engine/chessSteg';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '2mb' }));

  app.post('/api/encode', (req, res) => {
    try {
      const { text, passphrase } = req.body ?? {};
      if (typeof text !== 'string' || text.length === 0) {
        res.status(400).json({ detail: 'Secret text message cannot be empty.' });
        return;
      }
      const key = typeof passphrase === 'string' ? passphrase : '';
      const result = runEncode(text, key);
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Encoding failed.';
      res.status(400).json({ detail: message });
    }
  });

  app.post('/api/decode', (req, res) => {
    try {
      const { pgn, passphrase } = req.body ?? {};
      if (typeof pgn !== 'string' || pgn.trim().length === 0) {
        res.status(400).json({ detail: 'PGN input cannot be empty.' });
        return;
      }
      const key = typeof passphrase === 'string' ? passphrase : '';
      const result = runDecode(pgn, key);
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Decoding failed.';
      res.status(400).json({ detail: message });
    }
  });

  app.post('/api/avalanche', (req, res) => {
    try {
      const { text_a, text_b, passphrase } = req.body ?? {};
      if (
        typeof text_a !== 'string' ||
        text_a.length === 0 ||
        typeof text_b !== 'string' ||
        text_b.length === 0
      ) {
        res
          .status(400)
          .json({ detail: 'Both Message A and Message B must be non-empty strings.' });
        return;
      }
      const key = typeof passphrase === 'string' ? passphrase : '';
      const result = runAvalanche(text_a, text_b, key);
      res.json(result);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Avalanche comparison failed.';
      res.status(400).json({ detail: message });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ChessSteg server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
