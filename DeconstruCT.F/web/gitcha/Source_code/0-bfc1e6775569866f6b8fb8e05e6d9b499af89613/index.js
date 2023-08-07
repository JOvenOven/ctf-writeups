const express = require("express");
const fs = require("fs");
const serveIndex = require("serve-index");
const cookieParser = require("cookie-parser");
const nunjucks = require("nunjucks");
const bodyParser = require("body-parser");

const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

const app = express();

const checkAdmin = (req, res) => {
  if (req.cookies["SECRET_COOKIE_VALUE"] === "thisisahugesecret") {
    return true;
  }
  return false;
};

nunjucks.configure("views", {
  autoescape: true,
  express: app,
});

app.use(cookieParser());
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use("/.git", express.static(".git/"), serveIndex(".git/", { icons: true }));

app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow: /.git/\nDisallow: /supersecret/");
});

app.get("/supersecret", async (req, res) => {
  if (checkAdmin(req, res)) {
    const results = await prisma.note.findMany();
    res.render("notes.html", { foo: "bar", notes: results });
  } else {
    res.redirect("/");
  }
});

app.get("/getnotedetails", async (req, res) => {
  if (checkAdmin(req, res)) {
    const { id } = req.query;
    const note = await prisma.note.findUnique({ where: { id: parseInt(id) } });
    res.send(
      nunjucks.renderString(`
      <div style="margin: 15px;">
        <h1 style="font-family: Roboto;">${note.title}</h1>
        <p>${note.content}</p>
      </div>
  `)
    );
  } else {
    res.redirect("/");
  }
});

app.post("/addnote", async (req, res) => {
  if (checkAdmin(req, res)) {
    await prisma.note.create({
      data: {
        title: req.body.title,
        content: req.body.content,
      },
    });
    res.status(200).send("Note added");
  } else {
    res.status(403).send("Forbidden");
  }
});

app.get("/viewsource", (req, res) => {
  if (checkAdmin(req, res)) {
    const data = fs.readFileSync("index.js", "utf8");
    res.type("text/javascript");
    res.send(`
        ${data}
    `);
  }
});

app.listen(8080, () => {
  console.log("Example app listening on port 8080!");
});
