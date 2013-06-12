var db = require("./database");
var config = require("./config");
var keyrings = require("./keyrings");
var users = require("./users");
var groups = require("./groups");
var async = require("async");

var COOKIE_NAME = "gnewpg_sid";

function Session(id, user, persistent) {
	this.id = id;
	this.user = user;
	this.persistent = persistent;
}

function createSession(con, user, persistent, callback) {
	db.getUniqueRandomString(con, 43, "sessions", "id", function(err, id) {
		if(err)
			return callback(err);

		var ret = new Session(id, user, persistent);
		db.insert(con, "sessions", { id: ret.id, user: ret.user.id, last_access: new Date(), persistent: persistent }, function(err) {
			if(err)
				callback(err);
			else
				callback(null, ret);
		});
	});
}

function destroySession(con, session, callback) {
	db.remove(con, "sessions", { id: session.id }, callback);
}

function getSession(con, id, callback) {
	db.getEntry(con, "sessions", [ "id", "user", "persistent" ], { id: id }, function(err, sessionRecord) {
		if(err || !sessionRecord)
			return callback(err, null);

		db.update(con, "sessions", { last_access : new Date() }, { id: id }, function(err) {
			if(err)
				console.warn("Error updating session last_access time.", err);
		});

		users.getUser(con, sessionRecord.user, function(err, userRecord) {
			if(err)
				callback(err);
			else
				callback(null, new Session(sessionRecord.id, userRecord, sessionRecord.persistent));
		});
	});
}

function cleanInactiveSessions() {
	db.getConnection(function(err, con) {
		if(err)
			return console.warn("Error cleaning inactive sessions", err);

		con.query('DELETE FROM "sessions" WHERE NOT "persistent" AND $1 - "last_access" > $2', [ new Date(), config.sessionTimeout ], function(err) {
			if(err)
				console.warn("Error cleaning inactive sessions", err);

			con.done();
		});
	});
}

function cleanInactivePersistentSessions() {
	db.getConnection(function(err, con) {
		if(err)
			return console.warn("Error cleaning inactive sessions", err);

		con.query('DELETE FROM "sessions" WHERE "persistent" AND $1 - "last_access" > $2', [ new Date(), config.persistentSessionTimeout ], function(err) {
			if(err)
				console.warn("Error cleaning inactive sessions", err);

			con.done();
		});
	});
}

function scheduleInactiveSessionCleaning() {
	setInterval(function() { cleanInactiveSessions(); cleanInactivePersistentSessions(); }, config.sessionTimeout*100);
}

function sessionMiddleware(req, res, next) {
	async.auto({
		session : function(next) {
			if(!req.cookies[COOKIE_NAME])
				return next();

			getSession(req.dbCon, req.cookies[COOKIE_NAME], next);
		},
		group : function(next) {
			if(!req.query.groupToken)
				return next();

			groups.getGroupByToken(req.query.groupToken, next);
		},
		keyring : [ "session", "group", function(next, d) {
			req.session = d.session || { };

			if(req.session.user)
				req.keyring = new keyrings.UserKeyring(req.dbCon, req.session.user.id);
			else
				req.keyring = new keyrings.TemporaryUploadKeyring(req.dbCon);

			if(d.group)
				req.keyring = new keyrings.CombinedKeyring(req.keyring, new keyrings.GroupKeyring(req.dbCon, d.group.id), true);

			next();
		}]
	}, next);
}

function startSession(req, res, user, persistent, callback) {
	createSession(req.dbCon, user, persistent, function(err, session) {
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
		destroySession(req.dbCon, req.session, function(err) {
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