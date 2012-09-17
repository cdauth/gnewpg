var db = require("./database");
var users = require("./users");
var config = require("./config");

var COOKIE_NAME = "gnewpg_sid";

function Session(id, user, persistent) {
	this.id = id;
	this.user = user;
	this.persistent = persistent;
}

function createSession(user, persistent, callback) {
	db.getConnection(function(con) {
		db.getUniqueRandomString(44, "sessions", "id", function(id) {
			var ret = new Session(id, user);
			con.query('INSERT INTO "sessions" ( "id", "user", "last_access", "persistent" ) VALUES ( $1, $2, $3, $4 )', [ ret.id, ret.user.name, new Date(), persistent ], function(err) {
				if(err)
					throw err;
				callback && callback(ret);
			});
		}, con);
	});
}

function destroySession(session, callback) {
	db.getConnection(function(con) {
		con.query('DELETE FROM "sessions" WHERE "id" = $1', [ session.id ], function(err) {
			if(err)
				throw err;
			callback && callback();
		});
	});
}

function getSession(id, callback) {
	db.getConnection(function(con) {
		con.query('SELECT "id","user","persistent" FROM "sessions" WHERE "id" = $1', [ id ], function(err, res) {
			if(err)
				throw err;

			if(res.rowCount < 1)
				callback(null);
			else
			{
				con.query('UPDATE "sessions" SET "last_access" = $1 WHERE "id" = $2', [ new Date(), id ]);

				users.getUser(res.rows[0].user, function(user) {
					callback(new Session(res.rows[0].id, user, res.rows[0].persistent));
				});
			}
		});
	});
}

function cleanInactiveSessions() {
	db.getConnection(function(con) {
		con.query('DELETE FROM "sessions" WHERE NOT "persistent" AND $1 - "last_access" > $2', [ new Date(), config.sessionTimeout ]);
	});
}

function cleanInactivePersistentSessions() {
	db.getConnection(function(con) {
		con.query('DELETE FROM "sessions" WHERE "persistent" AND $1 - "last_access" > $2', [ new Date(), config.persistentSessionTimeout ]);
	});
}

function scheduleInactiveSessionCleaning() {
	setInterval(cleanInactiveSessions, Math.ceil(config.sessionTimeout*100));
	setInterval(cleanInactivePersistentSessions, Math.ceil(config.persistentSessionTimeout*100));
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

function startSession(req, res, user, persistent, callback) {
	createSession(user, persistent, function(session) {
		var options = { };
		if(persistent)
			options.maxAge = 315360000000; // 10 years
		res.cookie(COOKIE_NAME, session.id, options);
		
		callback && callback(session);
	});
}

function stopSession(req, res, callback) {
	if(req.session.user)
	{
		destroySession(req.session, function() {
			res.clearCookie(COOKIE_NAME);
			
			callback && callback();
		});
	}
}

exports.Session = Session;
exports.scheduleInactiveSessionCleaning = scheduleInactiveSessionCleaning;
exports.sessionMiddleware = sessionMiddleware;
exports.startSession = startSession;
exports.stopSession = stopSession;