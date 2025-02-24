const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
    // Get token from cookies
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid token' });
      }
      req.user = user; // attach decoded token data to req.user
      next();
    });
}

module.exports = authenticateToken;
