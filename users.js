var db = require("./database");
var crypto = require("crypto");

function User(name, password, email, openid, secret) {
	this.name = name;
	this.password = password;
	this.email = email;
	this.openid = openid;
	this.secret = secret;
}

function createUser(name, password, email, openid, callback) {
	db.getConnection(function(err, con) {
		if(err)
			callback && callback(err)
		else
		{
			db.getUniqueRandomString(44, "users", "secret", function(err, secret) {
				if(err)
					callback && callback(err);
				else
				{
					con.query('INSERT INTO "users" ( "name", "password", "email", "openid", "secret" ) VALUES ( $1, $2, $3, $4, $5 )', [ name, password, email, openid, secret ], function(err) {
						callback && callback(err);
					});
				}
			});
		}
	});
}

function getUser(name, callback) {
	db.getConnection(function(err, con) {
		if(err)
			callback(err);
		else
		{
			con.query('SELECT "name", "password", "email", "openid", "secret" FROM "users" WHERE LOWER("name") = LOWER($1)', [ name ], function(err, res) {
				if(err)
					callback(err);
				else if(res.rowCount < 1)
					callback(null, null);
				else
					callback(null, new User(res.rows[0].name, res.rows[0].password, res.rows[0].email, res.rows[0].openid, res.rows[0].secret));
			});
		}
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
