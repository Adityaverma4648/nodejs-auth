const express = require("express");
const passport = require("passport");
const cors = require('cors');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

//  importing utils here
const connectDB = require("./DB/connectDB");


//  importing routes here
const authRoutes = require("./routes/authRoutes");

dotenv.config();

const app = express();

// express instance
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

//  to make axios work
app.use(cors());
// app.use(cors({ methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"] }));
app.use(
  cors({
    allowedHeaders: ["Authorization", "Content-Type"],
  })
);

app.use("/auth", authRoutes);

app.get("/protected", (req, res) => {
  res.send("You are authorized to access this route!");
});

 
const start = async ()=>{
  try {
      await connectDB(process.env.MONGODB_URI);
     app.listen(process.env.PORT,console.log(`SERVER STARTED AT ${process.env.PORT}`));
  } catch (error) {
      console.log(`Connection failed : ${error}`)
  }

}
start();