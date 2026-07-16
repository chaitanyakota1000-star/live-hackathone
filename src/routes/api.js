const express = require('express');
const router = express.Router();

// Placeholder so the container has something real to respond with -
// lets you verify the full docker-compose stack (nginx -> backend -> db)
// works end-to-end before any real feature logic exists.
//
// Dev 3: this is where the real MVP routes go, roughly:
//   POST /api/sites            - add a URL to monitor
//                                 (validate/block internal & non-http(s) URLs - SSRF risk)
//   GET  /api/sites            - list sites, scoped to req.user (admin: all, user: owner_id = req.user.id)
//   POST /api/sites/:id/check  - manual "Check Now": fetch page, hash, diff vs last snapshot,
//                                 send diff to Gemini, store the returned summary/severity
//   GET  /api/sites/:id        - IMPORTANT: check ownership (owner_id or admin) before returning -
//                                 this is the classic IDOR spot (user A requesting user B's site by id)
router.get('/ping', (req, res) => {
  res.json({ pong: true });
});

module.exports = router;
