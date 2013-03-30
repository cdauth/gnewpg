var db = require("./database");
var utils = require("./utils");

function createUser(con, id, password, email, openid, locale, callback) {
	db.getUniqueRandomString(con, 43, "users", "secret", function(err, secret) {
		if(err) { callback(err); return; }
		
		db.insert(con, "users", { id: id, password: utils.encodePassword(password), email: email, openid: openid, locale: locale, secret: secret }, callback);
	});
}

function getUser(con, id, callback) {
	db.getEntry(con, "users", "*", { id: id }, callback);
}

function userExists(con, id, callback) {
	db.entryExists(con, "users", { id: id }, callback);
}

function updateUser(con, id, fields, callback) {
	db.update(con, "users", fields, { id: id }, callback);
}

function getUserByOpenId(con, openid, callback) {
	db.getEntry(con, "users", "*", { openid: openid }, callback);
}

exports.createUser = createUser;
exports.getUser = getUser;
exports.userExists = userExists;
exports.updateUser = updateUser;
exports.getUserByOpenId = getUserByOpenId;