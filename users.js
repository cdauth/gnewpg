var db = require("./database");
var crypto = require("crypto");

function User(name, password, email, openid) {
	this.name = name;
	this.password = password;
	this.email = email;
	this.openid = openid;
}

function createUser(user, callback) {
	db.getConnection(function(con) {
		con.query('INSERT INTO "users" ( "name", "password", "email", "openid" ) VALUES ( $1, $2, $3, $4 )', [ user.name, user.password, user.email, user.openid ], function(err) {
			if(err)
				throw err;
			callback && callback();
		});
	});
}

function getUser(name, callback) {
	db.getConnection(function(con) {
		con.query('SELECT "name", "password", "email", "openid" FROM "users" WHERE LOWER("name") = LOWER($1)', [ name ], function(err, res) {
			if(err)
				throw err;
			if(res.rowCount < 1)
				callback(null);
			else
				callback(new User(res.rows[0].name, res.rows[0].password, res.rows[0].email, res.rows[0].openid));
		});
	});
}

function encodePassword(password) {
	var sha = crypto.createHash("sha256");
	sha.update(password);
	return sha.digest("base64");
}

function checkPassword(user, password) {
	return encodePassword(password) == user.password;
}

exports.User = User;
exports.createUser = createUser;
exports.getUser = getUser;
exports.encodePassword = encodePassword;
exports.checkPassword = checkPassword;
