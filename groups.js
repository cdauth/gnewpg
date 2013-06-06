var db = require("./database");
var pgp = require("node-pgp");

function getGroupsByUser(userId) {
	var ret = new pgp.Fifo();
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		ret._add(db.getEntries(con, "groups_users_with_groups", "*", { user: userId }));
		ret._end();
		con.done();
	});
	return ret.recursive();
}

function createGroup(title, callback) {
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
				options.title = title;
				options.perm_searchengines = false;
				options.perm_addkeys = false;

				db.insert(con, "groups", options, function(err) {
					con.done();
					callback(err, options);
				});
			});
		});
	});
}

function addUserToGroup(groupId, userId, callback, admin) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.insert(con, "groups_users", { group: groupId, user: userId, perm_admin: !!admin, perm_addkeys: !!admin }, callback);
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

function getGroup(id, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.getEntry(con, "groups", "*", { id: id }, callback);
		con.done();
	});
}

function getKeysOfGroup(id, callback) {
	var ret = new pgp.Fifo();
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		// TODO: Optimise this
		ret._add(db.getEntries(con, "groups_keyrings_keys", [ "key" ], { group: id }).map(function(it, next) {
			it = { id: it.key };
			db.getEntries(con, "groups_keyrings_identites", [ "identity" ], { group: id, identityKey: it.key }).map(function(it, next) { next(it.identity); }).toArraySingle(function(err, identities) {
				it.identities = identities;
				db.getEntries(con, "groups_keyrings_attributes", [ "attribute" ], { group: id, attributeKey: it.key }).map(function(it, next) { next(it.attribute); }).toArraySingle(function(err, attributes) {
					it.attributes = attributes;
					next(null, it);
				});
			});
		}));
		ret._end();

		// TODO: con.done()
	});
	return ret.recursive();
}

function getMemberSettings(groupId, userId, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.getEntry(con, "groups_users", [ "perm_admin", "perm_addkeys" ], { group: groupId, user: userId }, callback);
		con.done();
	});
}

exports.getGroupsByUser = getGroupsByUser;
exports.createGroup = createGroup;
exports.addUserToGroup = addUserToGroup;
exports.getGroupByToken = getGroupByToken;
exports.getGroup = getGroup;
exports.getKeysOfGroup = getKeysOfGroup;
exports.getMemberSettings = getMemberSettings;