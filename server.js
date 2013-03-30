var sessions = require("./sessions");
var config = require("./config");
var fs = require("fs");
var mails = require("./mails");
var async = require("async");
var db = require("./database");
var webserver = require("./web/server");
var hkp = require("node-pgp-hkp-server");
var keyrings = require("./keyrings");
var users = require("./users");
var utils = require("./utils");

if(!fs.existsSync(config.tmpDir))
	fs.mkdirSync(config.tmpDir, 0700);
if(!fs.existsSync(config.tmpDir+"/upload"))
	fs.mkdirSync(config.tmpDir+"/upload", 0700);

var hkpHostRegexp = new RegExp("^"+utils.quoteRegexp(config.personalHkpHostname).replace("%s", "(.+)")+"$");

async.series([
	function(next) {
		sessions.scheduleInactiveSessionCleaning();
		mails.loadPrivateKey(next);
	},
	db.initialise,
	webserver.startServer,
	function(next) {
		if(!config.hkpHostname)
			return next();

		hkp(function(req, callback) {
			db.getConnection(function(err, con) {
				if(err)
					return callback(err);

				var m = req.host.match(hkpHostRegexp);
				if(!m)
					return callback(null, new keyrings.AnonymousKeyring(con));

				users.getUserBySecret(con, m[1], function(err, user) {
					if(err || !user)
						return callback(err || "Unknown user");

					return callback(null, new keyrings.UserKeyring(con, user.id));
				});
			});
		}, next);
	}
], function(err) {
	if(err)
		throw err;
	
	console.log("Server started");
});