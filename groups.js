var db = require("./database");
var pgp = require("node-pgp");

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

function addUserToGroup(groupId, userId, settings, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.insert(con, "groups_users", pgp.utils.extend({ }, settings, { group: groupId, user: userId }), callback);
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

function updateGroup(id, fields, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.update(con, "groups", fields, { id: id }, callback);
		con.done();
	});
}

/*function getKeysOfGroup(id) {
	var ret = new pgp.Fifo();
	db.getConnection(function(err, con) {
		if(err)
			return ret._end(err);

		var now = (new Date()).getTime();
		var current = null;
		db.getEntries(con, "groups_keyrings_keys_with_sub", "*", { group: id }, 'ORDER BY "key"').forEachSeries(function(it, next) {
			if(current == null || current.id != it.key) {
				if(current != null)
					ret._add(__fixPrimaryIdentity(current));

				current = { id: it.key, identities: { }, attributes: { } };
			}

			if(current.type == "key")
				pgp.utils.extend(current, { primary_identity: it.id, expired: it.expires && it.expires.getTime() <= now, revoked: it.revoked });
			else if(current.type == "identity")
				current.identities.push({ id: it.id, expired: it.expires && it.expires.getTime() <= now, revoked: it.revoked, nameTrust: it.nameTrust, emailTrust: it.emailTrust });
			else if(current.type == "attribute")
				current.attributes.push({ id: it.id, expired: it.expires && it.expires.getTime() <= now, revoked: it.revoked, trust: it.nameTrust });

			next();
		}, function(err) {
			con.done();

			if(err)
				return ret._end(err);

			if(current != null)
				ret._add(__fixPrimaryIdentity(current));
			ret._end();
		});
	});
	return ret;
}*/

function getMemberSettings(groupId, userId, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.getEntry(con, "groups_users", [ "perm_admin", "perm_addkeys", "perm_removekeys", "list" ], { group: groupId, user: userId }, callback);
		con.done();
	});
}

function updateMemberSettings(groupId, userId, settings, callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		db.update(con, "groups_users", settings, { group: groupId, user: userId }, callback);
		con.done();
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

/*function __fixPrimaryIdentity(keyInfo) {
	if(keyInfo.primary_identity == null)
		return keyInfo;

	var newIdentity = null;
	for(var i=keyInfo.identities.length-1; i>=0; i--) {
		if(keyInfo.identities[i].id == keyInfo.primary_identity)
			return keyInfo;
		if(!keyInfo.identities[i].revoked && !keyInfo.identities[i].expired)
			newIdentity = keyInfo.identities[i].id;
	}
	keyInfo.primary_identity = newIdentity;
	return keyInfo;
}*/

exports.getGroupsByUser = getGroupsByUser;
exports.createGroup = createGroup;
exports.addUserToGroup = addUserToGroup;
exports.getGroupByToken = getGroupByToken;
exports.getGroup = getGroup;
exports.updateGroup = updateGroup;
//exports.getKeysOfGroup = getKeysOfGroup;
exports.getMemberSettings = getMemberSettings;
exports.getMembers = getMembers;
exports.updateMemberSettings = updateMemberSettings;