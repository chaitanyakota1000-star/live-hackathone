import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import apiRouter from './routes/api.js';

const app = express();

// Security: Apply strict security headers ONLY to API routes to prevent breaking frontend inline scripts
app.use('/api', helmet());

// Security: Allow cross-origin requests from the GitHub Pages frontend
app.use(cors({
  origin: ['https://chaitanyakota1000-star.github.io', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Security: Limit request body size to 1MB to prevent DoS
app.use(express.json({ limit: '1mb' }));

// Mount the API router
app.use('/api', apiRouter);

// Serve static frontend files
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, '../public')));

// Catch-all route to serve the main HTML file (useful for SPAs)
app.get('*', (req, res) => {
    if (req.originalUrl.startsWith('/api')) return next();
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Health check
app.get('/api/ping', (req, res) => res.send('pong'));

// Generic error handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend server is running on port ${PORT}`);
});
