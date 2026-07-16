require('dotenv').config();
const express = require('express');
const apiRouter = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

// Small body size limit - we're not accepting file uploads in this MVP,
// so there's no reason to allow large request bodies.
app.use(express.json({ limit: '100kb' }));

app.use('/api', apiRouter);

// Used by teammates/docker to confirm the container is actually up.
// Deliberately not auth-gated - it should reveal nothing sensitive.
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Centralized error handler - MUST stay last.
// Judges will be looking for stack traces leaking into responses on a
// security tool, so full error details go to the server logs only;
// the client only ever gets a generic message.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Backend listening on port ${PORT}`);
});
