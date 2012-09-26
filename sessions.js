var db = require("./database");
var config = require("./config");

var COOKIE_NAME = "gnewpg_sid";

function Session(id, user, persistent) {
	this.id = id;
	this.user = user;
	this.persistent = persistent;
}

function createSession(user, persistent, callback) {
	db.getUniqueRandomString(43, "sessions", "id", function(err, id) {
		if(err)
			callback(err);
		else
		{
			var ret = new Session(id, user);
			db.insert("sessions", { id: ret.id, user: ret.user.id, last_access: new Date(), persistent: persistent }, function(err) {
				if(err)
					callback(err);
				else
					callback(null, ret);
			});
		}
	});
}

function destroySession(session, callback) {
	db.delete("sessions", { id: session.id }, callback);
}

function getSession(id, callback) {
	db.getEntry("sessions", [ "id", "user", "persistent" ], { id: id }, function(err, sessionRecord) {
		if(err)
			callback(err);
		else if(!sessionRecord)
			callback(null, null);
		else
		{
			db.update("sessions", { last_access : new Date() }, { id: id }, function(err) {
				if(err)
					console.warn("Error updating session last_access time.", err);
			});

			db.getEntry("users", "*", { id: sessionRecord.user }, function(err, userRecord) {
				if(err)
					callback(err);
				else
					callback(null, new Session(sessionRecord.id, userRecord, sessionRecord.persistent));
			});
		}
	});
}

function cleanInactiveSessions() {
	db.query('DELETE FROM "sessions" WHERE NOT "persistent" AND $1 - "last_access" > $2', [ new Date(), config.sessionTimeout ], function(err) {
		if(err)
			console.warn("Error cleaning inactive sessions", err);
	});
}

function cleanInactivePersistentSessions() {
	db.query('DELETE FROM "sessions" WHERE "persistent" AND $1 - "last_access" > $2', [ new Date(), config.persistentSessionTimeout ], function(err) {
		if(err)
			console.warn("Error cleaning inactive permanent sessions", err);
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