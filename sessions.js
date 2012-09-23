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
	db.getConnection(function(err, con) {
		if(err)
			callback(err);
		else
		{
			db.getUniqueRandomString(43, "sessions", "id", function(err, id) {
				if(err)
					callback(err);
				else
				{
					var ret = new Session(id, user);
					con.query('INSERT INTO "sessions" ( "id", "user", "last_access", "persistent" ) VALUES ( $1, $2, $3, $4 )', [ ret.id, ret.user.id, new Date(), persistent ], function(err) {
						if(err)
							callback(err);
						else
							callback(null, ret);
					});
				}
			}, con);
		}
	});
}

function destroySession(session, callback) {
	db.getConnection(function(err, con) {
		if(err)
			callback && callback(err);
		else
		{
			con.query('DELETE FROM "sessions" WHERE "id" = $1', [ session.id ], function(err) {
				callback && callback(err);
			});
		}
	});
}

function getSession(id, callback) {
	db.getConnection(function(err, con) {
		if(err)
			callback(err);
		else
		{
			con.query('SELECT "id","user","persistent" FROM "sessions" WHERE "id" = $1', [ id ], function(err, res) {
				if(err)
					callback(err);
				else if(res.rowCount < 1)
					callback(null, null);
				else
				{
					con.query('UPDATE "sessions" SET "last_access" = $1 WHERE "id" = $2', [ new Date(), id ]);

					users.getUser(res.rows[0].user, function(err, user) {
						if(err)
							callback(err);
						else
							callback(null, new Session(res.rows[0].id, user, res.rows[0].persistent));
					});
				}
			});
		}
	});
}

function cleanInactiveSessions() {
	db.getConnection(function(err, con) {
		if(err)
			console.warn("Error cleaning inactive sessions", err);
		else
			con.query('DELETE FROM "sessions" WHERE NOT "persistent" AND $1 - "last_access" > $2', [ new Date(), config.sessionTimeout ]);
	});
}

function cleanInactivePersistentSessions() {
	db.getConnection(function(err, con) {
		if(err)
			console.warn("Error cleaning inactive permanent sessions", err);
		else
			con.query('DELETE FROM "sessions" WHERE "persistent" AND $1 - "last_access" > $2', [ new Date(), config.persistentSessionTimeout ]);
	});
}

function scheduleInactiveSessionCleaning() {
	setInterval(function() { cleanInactiveSessions(); cleanInactivePersistentSessions(); }, Math.ceil(config.sessionTimeout*100));
}

function sessionMiddleware(req, res, next) {
	var cb = function(err, session) {
		if(err)
			next(err);
		else
		{
			req.session = session || { };
			next();
		}
	};
	
	if(req.cookies[COOKIE_NAME])
		getSession(req.cookies[COOKIE_NAME], cb);
	else
		cb();
}

function startSession(req, res, user, persistent, callback) {
	createSession(user, persistent, function(err, session) {
		if(err)
			callback && callback(err);
		else
		{
			var options = { };
			if(persistent)
				options.maxAge = 315360000000; // 10 years
			res.cookie(COOKIE_NAME, session.id, options);
			
			callback && callback(null, session);
		}
	});
}

function stopSession(req, res, callback) {
	if(req.session.user)
	{
		destroySession(req.session, function(err) {
			if(err)
				callback && callback(err);
			else
			{
				res.clearCookie(COOKIE_NAME);
				callback && callback(null);
			}
		});
	}
}

exports.Session = Session;
exports.scheduleInactiveSessionCleaning = scheduleInactiveSessionCleaning;
exports.sessionMiddleware = sessionMiddleware;
exports.startSession = startSession;
exports.stopSession = stopSession;