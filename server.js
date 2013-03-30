var sessions = require("./sessions");
var config = require("./config");
var fs = require("fs");
var mails = require("./mails");
var async = require("async");
var db = require("./database");
var webserver = require("./web/server");

if(!fs.existsSync(config.tmpDir))
	fs.mkdirSync(config.tmpDir, 0700);
if(!fs.existsSync(config.tmpDir+"/upload"))
	fs.mkdirSync(config.tmpDir+"/upload", 0700);

async.series([
	function(next) {
		sessions.scheduleInactiveSessionCleaning();
		mails.loadPrivateKey(next);
	},
	db.initialise,
	webserver.startServer
], function(err) {
	if(err)
		throw err;
	
	console.log("Server started");
});