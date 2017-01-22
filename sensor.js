const request = require('request');
const crypto = require('crypto');
const publicIp = require('public-ip');
const fs = require('fs');
function Sensor(server) {
	var httpIdx = server.indexOf("http://");
	httpIdx = httpIdx == -1 ? server.indexOf("https://") : httpIdx;
	if((httpIdx == -1 && server.indexOf(":") == -1) || server.substr(httpIdx).indexOf(":") == -1) {
		server += ":85"; //Default HoneyMesh port.
	}
	if(httpIdx == -1) {
		server = "http://" + server 
	}
	console.log("Logging to server: " + server);
    this.attackers = {};
	var instance = this;
    publicIp.v4().then(ip => {
        instance.id = crypto.createHash('sha256').update(ip).digest('hex');
    });	

    this.addAttacker = function(ip, fingerprint) {
		console.log("Unhashed fingerprint: " + fingerprint)
        instance.attackers[ip] = crypto.createHash('sha256').update(fingerprint).digest('hex');
    }

    this.logCommand = function(ip, command, fingerprint) {
        if(!fingerprint && instance.attackers[ip]) {
            fingerprint = instance.attackers[ip];
        }
        request(server + "/logCommand?id=" + instance.id + "&attacker=" + ip + "&timestamp=" + new Date().toISOString() + (fingerprint ? "&fingerprint=" + fingerprint : "") + "&command=" + command, function(err, resp) {
			if(err) {
				console.log("ERR: " + err);
			}
		});
    }
}
module.exports = Sensor;
