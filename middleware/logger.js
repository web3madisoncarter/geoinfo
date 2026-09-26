const fs = require('fs');
const path = require('path');

const logPath = path.join(__dirname, '../logs/security.log');

function logBlockedRequest(ip, reason) {
    console.log("IP Block Request Called !!!!!!!!!!!!!");
    const entry = `[${new Date().toISOString()}] Blocked IP: ${ip} | Reason: ${reason}\n`;
    fs.appendFileSync(logPath, entry);
    console.log(entry);
}

// Export the function so it can be used in other files
module.exports = {
    logBlockedRequest,
};