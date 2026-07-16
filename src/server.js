import express from 'express';
import apiRouter from './routes/api.js';

const app = express();
app.use(express.json());

// Mount the API router
app.use('/api', apiRouter);

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
