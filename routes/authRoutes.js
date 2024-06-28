const express = require("express");
const passport = require("passport");
const User = require("../Model/User");
const generateToken = require("../utils/JWT");
const jwt = require("jsonwebtoken");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const authMiddleware = require("../middleware/authMiddleware");
// app instance
const router = express.Router();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true,
    },
    (accessToken, refreshToken, profile, done) => {
      // You can perform actions here like saving the user to the database
      return done(null, profile, accessToken, refreshToken);
    }
  )
);

router.post("/getUserDetails", authMiddleware, async (req, res) => {
  console.log(req);
  const { token } = req.body;
  if (token == null) return res.status(400).send("Token Is null");
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(404);
    req.user = user;
    res.status(200).json(req.user);
  });
});

router.post("/register", async (req, res) => {
  const { userName, email, password } = req.body;

  if (!userName || !email || !password) {
    res.status(400).json({ message: "Fill all the entries!" });
  }
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400).json({ message: "UserEmail Already Exists!" });
  }
  const user = await User.create({
    userName,
    email,
    password,
  });

  if (user) {
    res.status(200).json({ message: "successfully registered!" });
    //  redirected on login
  } else {
    res.status(400).json({ message: "Server Error" });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  console.log(req.body);
  const user = await User.findOne({ email });
  console.log(user);
  if (user && (await user.matchPassword(password))) {
    const token = generateToken(user);
    res.status(200).json({ token: token });
  } else if (user && !(await user.matchPassword(password))) {
    res.status(400).json({ message: "Incorrect password!" });
  } else {
    res.status(400).json({
      message:
        "User not found:Please register yourself first or try another email",
    });
  }
});

router.post("/logout", authMiddleware, (req, res) => {
  const { token } = req.body;
  jwt.sign(token, process.env.JWT_SECRET, { expiresIn: 1 }, (logout, err) => {
    if (logout) {
      res.status(200).json({ message: "Successfully LoggedOut!" });
    } else if (err) {
      res.status(400).json({ message: "Something went Wrong" });
    }
  });
});

router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign({ user }, process.env.JWT_SECRET);
    res.json({ token });
  }
);

module.exports = router;
