const express = require("express");
const path = require("path");
const serveIndex = require("serve-index");

const app = express();

app.use(express.static("public"));

app.use("/.git", express.static(".git/"), serveIndex(".git/", { icons: true }));

app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow: /.git/\nDisallow: /supersecret/");
});

app.listen(8080, () => {
  console.log("Example app listening on port 8080!");
});
