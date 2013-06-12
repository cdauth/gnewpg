var db = require("./database");
var pgp = require("node-pgp");
var async = require("async");

function getGroup(id, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.getEntry(con, "groups", "*", { id: id }, callback);
		con.done();
	});
}

function getGroupByToken(token, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.getEntry(con, "groups", "*", { token: token }, callback);
		con.done();
	});
}

function createGroup(callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.getUniqueRandomString(con, 8, "groups", "id", function(err, id) {
			if(err) {
				con.done();
				return callback(err);
			}

			db.getUniqueRandomString(con, 43, "groups", "token", function(err, token) {
				if(err) {
					con.done();
					return callback(err);
				}

				var options = { };
				options.id = id;
				options.token = token;
				options.title = "";
				options.perm_searchengines = false;
				options.perm_addkeys = false;
				options.perm_removekeys = false;

				db.insert(con, "groups", options, function(err) {
					con.done();
					callback(err, options);
				});
			});
		});
	});
}

function updateGroup(id, fields, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.update(con, "groups", fields, { id: id }, callback);
		con.done();
	});
}

function removeGroup(groupId, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(con);

		async.parallel([
			function(next) {
				db.remove(con, "groups_keyrings_identities", { group: groupId }, next);
			},
			function(next) {
				db.remove(con, "groups_keyrings_attributes", { group: groupId }, next);
			},
			function(next) {
				db.remove(con, "groups_keyrings_keys", { group: groupId }, next);
			},
			function(next) {
				db.remove(con, "groups_users", { group: groupId }, next);
			},
			function(next) {
				db.remove(con, "groups", { id: groupId }, next);
			}
		], function(err) {
			con.done();
			callback(err);
		});
	});
}

function getMembers(groupId, filter) {
	var ret = new pgp.Fifo();
	db.getConnection(function(err, con) {
		if(err)
			return ret._end(err);

		ret._add(db.getEntries(con, "groups_users", [ "user", "perm_admin", "perm_addkeys", "perm_removekeys" ], pgp.utils.extend({ }, filter, { group: groupId })));
		ret._end();
		con.done();
	});
	return ret.recursive();
}

function getMemberSettings(groupId, userId, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.getEntry(con, "groups_users", [ "perm_admin", "perm_addkeys", "perm_removekeys", "list" ], { group: groupId, user: userId }, callback);
		con.done();
	});
}

function getGroupsByUser(userId) {
	var ret = new pgp.Fifo();
	db.getConnection(function(err, con) {
		if(err)
			return ret._end(err);

		ret._add(db.getEntries(con, "groups_users_with_groups", "*", { user: userId }));
		ret._end();
		con.done();
	});
	return ret.recursive();
}

function addMember(groupId, userId, settings, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.insert(con, "groups_users", pgp.utils.extend({ }, settings, { group: groupId, user: userId }), callback);
		con.done();
	});
}

function updateMember(groupId, userId, settings, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.update(con, "groups_users", settings, { group: groupId, user: userId }, callback);
		con.done();
	});
}

function removeMember(groupId, userId, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.remove(con, "groups_users", { group: groupId, user: userId }, callback);
	});
}

exports.getGroup = getGroup;
exports.getGroupByToken = getGroupByToken;
exports.createGroup = createGroup;
exports.updateGroup = updateGroup;
exports.removeGroup = removeGroup;
exports.getMembers = getMembers;
exports.getMemberSettings = getMemberSettings;
exports.getGroupsByUser = getGroupsByUser;
exports.addMember = addMember;
exports.updateMember = updateMember;
exports.removeMember = removeMember;