var db = require("./database");
var users = require("./users");
var config = require("./config");

var COOKIE_NAME = "gnewpg_sid";

function Session(id, user) {
	this.id = id;
	this.user = user;
}

function createSession(user, callback) {
	db.getConnection(function(con) {
		db.getUniqueRandomString(32, "sessions", "id", function(id) {
			var ret = new Session(id, user);
			con.query('INSERT INTO "sessions" ( "id", "user", "last_access" ) VALUES ( $1, $2, $3 )', [ ret.id, ret.user.name, new Date() ], function(err) {
				if(err)
					throw err;
				callback(ret);
			});
		}, con);
	});
}

function getSession(id, callback) {
	db.getConnection(function(con) {
		con.query('SELECT "id","user" FROM "sessions" WHERE "id" = $1', [ id ], function(err, res) {
			if(err)
				throw err;
			if(res.length < 1)
				callback(null);
			
			con.query('UPDATE "sessions" SET "last_access" = $1 WHERE "id" = $2', [ new Date(), id ]);

			users.getUser(res[0].user, function(user) {
				callback(new Session(ret[0].id, user));
			});
		});
	});
}

function cleanInactiveSessions() {
	db.getConnection(function(con) {
		var q = con.query('DELETE FROM "sessions" WHERE $1 - "last_access" > $2', [ new Date(), config.sessionTimeout ]);
	});
}

function scheduleInactiveSessionCleaning() {
	setInterval(cleanInactiveSessions, Math.ceil(config.sessionTimeout/10));
}

function sessionMiddleware(req, res, next) {
	var cb = function(session) {
		req.session = session || { };
		next();
	};
	
	if(req.cookies[COOKIE_NAME])
		getSession(req.cookies[COOKIE_NAME], cb);
	else
		cb();
}

function startSession(res, user, callback) {
	createSession(user, function(session) {
		res.cookie(COOKIE_NAME, session.id);
		
		if(callback)
			callback(session);
	});
}

exports.Session = Session;
exports.scheduleInactiveSessionCleaning = scheduleInactiveSessionCleaning;
exports.sessionMiddleware = sessionMiddleware;
exports.startSession = startSession;