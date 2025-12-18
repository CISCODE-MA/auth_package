const jwt = require("jsonwebtoken");

const tenantMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1]; // Extract JWT
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.tenantId = decoded.tenantId; // Attach tenant ID to request
        next();
    } catch (error) {
        res.status(403).json({ error: "Invalid token" });
    }
};

module.exports = tenantMiddleware;
