const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.status(400).send("Token Is null");
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(404);
    req.user = user;
    next();
  });
}

module.exports = authMiddleware;
