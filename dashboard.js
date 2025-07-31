const express = require("express");
const fs = require("fs");
const path = require("path");
const redis = require("redis").createClient(); // reuse same Redis if needed
const router = express.Router();

const LOG_DIR = path.join(__dirname, "site-logs");

router.get("/stats", (req, res) => {
    try {
      const stats = JSON.parse(fs.readFileSync("./botCount.json", "utf8"));
      res.json(stats);
    } catch {
      res.status(500).json({ error: "Failed to read stats" });
    }
  });
  
  router.get("/sites", (req, res) => {
    const files = fs.readdirSync(LOG_DIR);
    const data = files.map(file => {
      const contents = fs.readFileSync(path.join(LOG_DIR, file), "utf8");
      return {
        domain: file.replace(".log", ""),
        count: contents.trim().split("\n").length
      };
    });
    res.json(data);
  });
  
  router.get("/log/:domain", (req, res) => {
    const domain = req.params.domain;
    const filePath = path.join(LOG_DIR, `${domain}.log`);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Log not found" });
    }
    const log = fs.readFileSync(filePath, "utf8");
    res.type("text/plain").send(log);
  });
  
  router.get("/health", (req, res) => {
    const health = {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date(),
    };
    res.json(health);
  });
  

module.exports = router;
