var db = require("./database");
var utils = require("./utils");

function createUser(con, id, password, email, openid, callback) {
	db.getUniqueRandomString(con, 43, "users", "secret", function(err, secret) {
		if(err) { callback(err); return; }
		
		db.insert(con, "users", { id: id, password: utils.encodePassword(password), email: email, openid: openid, secret: secret }, callback);
	});
}

function getUser(con, id, callback) {
	db.getEntry(con, "users", "*", { id: id }, callback);
}

function userExists(con, id, callback) {
	db.entryExists(con, "users", { id: id }, callback);
}

exports.createUser = createUser;
exports.getUser = getUser;
exports.userExists = userExists;