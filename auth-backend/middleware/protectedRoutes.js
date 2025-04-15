const jwt = require('jsonwebtoken');

const protectedRoutes = (req, res, next) => {
    const token = req.headers['authorization'];
        if (!token) {
            return res.status(401).json({ error: 'Access denied. No token provided.' });
        }

        try {
            const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
            if (decoded.role !== requiredRole) {
                return res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
            }
            req.user = decoded;
            next();
        } catch (err) {
            res.status(403).json({ error: 'Invalid or expired token.' });
        }
};

module.exports = protectedRoutes;