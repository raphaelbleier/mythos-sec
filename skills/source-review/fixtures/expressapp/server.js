// Fixture for `scripts/sourcemap --selftest`. Deliberately flawed, never run.
const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");

const app = express();
app.use(cors());

function requireAuth(req, res, next) {
  next();
}

app.get("/health", (req, res) => res.send("ok"));

app.get("/profile", requireAuth, (req, res) => res.json({ id: req.user.id }));

app.post("/run", (req, res) => {
  exec("ping -c1 " + req.body.host, (err, out) => res.send(out));
});

module.exports = app;
