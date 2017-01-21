var express = require('express');
var fs = require('fs');
const IP_WHITELIST = JSON.parse(fs.readFileSync('whitelist.json'));
const LOG_FILE = "honeymesh.log"
var app = express();
var id = 1;

app.use(function(req, res, next) {
	if(IP_WHITELIST.indexOf(req.connection.remoteAddress == -1) {
		res.end("You are not permitted to perform that action.");
		return;
	}
	next();
})

/**
 * Command log entries are structured with a few fields:
 * id: The sensor id reporting the attack
 * attacker: The ip address of the attacker
 * timestamp: The ISO-8601 formatted time at which the attack occurred. If omitted, current time is assumed.
 * fingerprint (optional): A unique fingerprint hash for the attacker
 * command: the command used by the attacker
 */
app.get('/logCommand', function(req, res) {
	var requiredFields = ['id', 'attacker', 'command'];
	for(var i = 0; i < requiredFields.length; i++) {
		if(!req.query[requiredFields[i]]) {
			req.end("Missing field ''" + requiredFields[i] + "'");
			return;
		}
	}
	var id = req.query.id;
	var attacker = req.query.attacker;
	var timestamp = req.query.timestamp || new Date().toISOString();
	var fingerprint = req.query.fingerprint || "";
	var command = req.query.command;
	log("[" + id + "] " + attacker + (req.query.fingerprint ? "(" + fingerprint + ")" : "") + ": " + command)
	res.end();
})

/*app.get("/getId", function(req, res) {
	res.end(id++);
})*/

function log(data) {
	var str = "[" + new Date().toISOString() + "] " + data
	console.log(str);
	fs.appendFile(LOG_FILE, str + "\r\n");
}
