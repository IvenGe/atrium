const express = require("express");

const app = express();
app.use(express.json());

app.get("/healthz", (req, res) => res.json({ status: "ok" }));
app.get("/api/customers", (req, res) => res.json([]));

// The hub delivers events this app listens to (see hub.manifest.yaml) here.
app.post("/hub/events", (req, res) => {
  console.log("hub event", req.body.event);
  res.sendStatus(204);
});

app.listen(process.env.PORT || 4000);
