const http = require("http");
const url = require("url");
const { google } = require("googleapis");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const cookieParser = require("cookie-parser");

require("dotenv").config();

const oauth2Client = new google.auth.OAuth2(
  process.env.YOUR_CLIENT_ID,
  process.env.YOUR_CLIENT_SECRET,
  process.env.YOUR_REDIRECT_URL
);

const googleAuth = google.oauth2({
  version: "v2",
  auth: oauth2Client,
});

const scopes = [
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
];

let userCredential = null;

async function main() {
  const app = express();

  app.use(
    cors({
      origin: "http://localhost:8080",
    })
  );
  app.use(
    session({
      secret: "your_secure_secret_key",
      resave: false,
      saveUninitialized: false,
    })
  );
  app.use(cookieParser());
  app.get("/", async (req, res) => {
    const state = crypto.randomBytes(32).toString("hex");
    req.session.state = state;

    const authorizationUrl = oauth2Client.generateAuthUrl({
      access_type: "offline",
      scope: scopes,
      include_granted_scopes: true,
      state: state,
    });

    res.redirect(authorizationUrl);
  });

  app.get("/oauth2callback", async (req, res) => {
    let q = url.parse(req.url, true).query;

    if (q.error) {
      console.log("Error:" + q.error);
    } else if (q.state !== req.session.state) {
      console.log("State mismatch. Possible CSRF attack");
      res.end("State mismatch. Possible CSRF attack");
    } else {
      let { tokens } = await oauth2Client.getToken(q.code);
      console.log("this is token", tokens);
      oauth2Client.setCredentials(tokens);
      userCredential = tokens;

      const googleUserInfo = await googleAuth.userinfo.get();

      if (!googleUserInfo) {
        res.status(400).json({ success: false, msg: "Invalid credentials" });
      }
      res.status(200).cookie("token", tokens.id_token).json({
        success: true,
        token: tokens.id_token,
        data: googleUserInfo.data,
      });
    }
  });

  app.get("/cookie", (req, res) => {
    res.send(req.cookies);
  });
  const server = http.createServer(app);
  server.listen(3000);
}
main().catch(console.error);
