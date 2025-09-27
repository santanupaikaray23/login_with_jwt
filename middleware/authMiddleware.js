const jwt = require("jsonwebtoken");
const User = require("../auth/userSchema"); 
const config = require("../config");

async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; 


    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, config.secert); 
    const user = await User.findById(decoded.id).select("_id email role");

    if (!user) {
      return res.status(401).json({ message: "Invalid user" });
    }

    req.user = user; 
    next();
  } catch (err) {
    console.error("Auth error:", err.message);
    return res.status(401).json({ message: "Unauthorized" });
  }
}

module.exports = authMiddleware;