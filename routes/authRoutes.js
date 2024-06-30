const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("../Model/User");
const generateToken = require("../utils/JWT");
const authMiddleware = require("../middleware/authMiddleware");
const dotenv = require("dotenv");

dotenv.config();

const router = express.Router();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, profile, done) => {
      // Check if user exists in the database

      console.log({ accessToken, refreshToken, profile });
      // try {
      //   let user = await User.findOne({ googleId: profile.id });
      //   if (!user) {
      //     user = new User({
      //       googleId: profile.id,
      //       displayName: profile.displayName,
      //       email: profile.emails[0].value,
      //     });
      //     await user.save();
      //   }
      //   done(null, user);
      // } catch (err) {
      //   done(err, null);
      // }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

router.post("/getUserDetails", authMiddleware, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).send("Token is null");
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    res.status(200).json(user);
  });
});

router.post("/register", async (req, res) => {
  const { userName, email, password } = req.body;
  if (!userName || !email || !password) {
    return res.status(400).json({ message: "Fill all the entries!" });
  }
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User Email Already Exists!" });
    }
    const user = new User({ userName, email, password });
    await user.save();
    res.status(201).json({ message: "Successfully registered!" });
  } catch (err) {
    res.status(500).json({ message: "Server Error" });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && (await user.matchPassword(password))) {
      const token = generateToken(user);
      res.status(200).json({ token });
    } else {
      res.status(400).json({ message: "Invalid email or password!" });
    }
  } catch (err) {
    res.status(500).json({ message: "Server Error" });
  }
});

router.post("/logout", authMiddleware, (req, res) => {
  const { token } = req.body;
  jwt.sign(token, process.env.JWT_SECRET, { expiresIn: 1 }, (logout, err) => {
    if (logout) {
      res.status(200).json({ message: "Successfully Logged Out!" });
    } else {
      res.status(400).json({ message: "Something went wrong" });
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
    const token = generateToken(req.user);
    res.json({ token });
  }
);

module.exports = router;
