const bannedIPs = new Set([
    // Add default banned IPs here, e.g. "192.168.0.1"
]);    

function isBanned(ip) {
    return bannedIPs.has(ip);
}

function banIP(ip) {
    bannedIPs.add(ip);
    // Optionally: Save to file or DB here
}

module.exports = {
    isBanned,
    banIP,
};
