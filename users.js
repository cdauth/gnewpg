var db = require("./database");
var utils = require("./utils");

function createUser(id, password, email, openid, callback) {
	db.getUniqueRandomString(43, "users", "secret", function(err, secret) {
		if(err) { callback(err); return; }
		
		db.insert("users", { id: id, password: utils.encodePassword(password), email: email, openid: openid, secret: secret }, callback);
	});
}

exports.createUser = createUser;