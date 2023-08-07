const express = require("express");
const path = require("path");
const serveIndex = require("serve-index");
const cookieParser = require("cookie-parser");

const app = express();

app.use(cookieParser());
app.use(express.static("public"));

app.use("/.git", express.static(".git/"), serveIndex(".git/", { icons: true }));

app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow: /.git/\nDisallow: /supersecret/");
});

app.get("/supersecret", (req, res) => {
  if (req.cookies["SECRET_COOKIE_VALUE"] === "thisisahugesecret") {
    res.send("You found the secret!");
  } else {
    res.redirect("/");
  }
});

app.listen(8080, () => {
  console.log("Example app listening on port 8080!");
});
