const request = require('request');
const crypto = require('crypto');
const publicIp = require('public-ip');
const fs = require('fs');
function Sensor(server) {
    this.attackers = {};
    publicIp.v4().then(ip => {
        this.id = crypto.createHash('sha256').update(ip).digest('base64');
    });

    this.addAttacker = function(ip, fingerprint) {
        attackers[ip] = fingerprint;
    }

    this.logCommand = function(ip, command, fingerprint) {
        if(!fingerprint && attackers[ip]) {
            fingerprint = attackers[ip];
        }
        request(server, "/logCommand?id=" + this.id + "&attacker=" + ip + "&timestamp=" + new Date().toISOString() + (fingerprint ? "&fingerprint=" + fingerprint : "") + "&command=" + command);
    }
}
module.exports = Sensor;
