const rateLimit = require("express-rate-limit");

const secretHeader = process.env.SECRET_HEADER_VALUE;

function generalLimiter(ip) {
	rateLimit({
		windowMs: 60 * 1000,
		max: 10,
		standardHeaders: true,
		legacyHeaders: false,
		message: { status: 429, error: "Too many requests, try again later." },
		skip: (req) => req.headers["x-secret-header"] === secretHeader,
	});
}

module.exports = {
    generalLimiter,
};
