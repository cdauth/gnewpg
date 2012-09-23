var db = require("./database");
var crypto = require("crypto");

function User(id, password, email, openid, secret) {
	this.id = id;
	this.password = password;
	this.email = email;
	this.openid = openid;
	this.secret = secret;
}

function createUser(id, password, email, openid, callback) {
	db.getConnection(function(err, con) {
		if(err)
			callback && callback(err)
		else
		{
			db.getUniqueRandomString(43, "users", "secret", function(err, secret) {
				if(err)
					callback && callback(err);
				else
				{
					con.query('INSERT INTO "users" ( "id", "password", "email", "openid", "secret" ) VALUES ( $1, $2, $3, $4, $5 )', [ id, password, email, openid, secret ], function(err) {
						callback && callback(err);
					});
				}
			});
		}
	});
}

function getUser(id, callback) {
	db.getConnection(function(err, con) {
		if(err)
			callback(err);
		else
		{
			con.query('SELECT "id", "password", "email", "openid", "secret" FROM "users" WHERE LOWER("id") = LOWER($1)', [ id ], function(err, res) {
				if(err)
					callback(err);
				else if(res.rowCount < 1)
					callback(null, null);
				else
					callback(null, new User(res.rows[0].id, res.rows[0].password, res.rows[0].email, res.rows[0].openid, res.rows[0].secret));
			});
		}
	});
}

function encodePassword(password) {
	var sha = crypto.createHash("sha256");
	sha.update(password);
	return sha.digest("base64").substring(0, 43);
}

function checkPassword(user, password) {
	return encodePassword(password) == user.password;
}

function identityIsInKeyring(userId, keyId, identityId, callback, con)
{
	db.xExists("users_keyrings_identities", { "user" : userId, "identityKey" : keyId, "identity" : identityId }, callback, con);
}

function attributeIsInKeyring(userId, keyId, attributeId, callback, con)
{
	db.xExists("users_keyrings_attributes", { "user" : userId, "attributeKey" : keyId, "attribute" : attributeId }, callback, con);
}

function addIdentityToKeyring(userId, keyId, identityId, callback, con)
{
	identityIsInKeyring(userId, keyId, identityId, function(err, is) {
		if(err)
			callback(err);
		else if(is)
			callback(null);
		else
			db.query('INSERT INTO "users_keyrings_identities" ( "user", "identityKey", "identity" ) VALUES ( $1, $2, $3 )', [ userId, keyId, identityId ], callback, con);
	}, con);
}

function addAttributeToKeyring(userId, keyId, attributeId, callback, con)
{
	attributeIsInKeyring(userId, keyId, attributeId, function(err, is) {
		if(err)
			callback(err);
		else if(is)
			callback(null);
		else
			db.query('INSERT INTO "users_keyrings_attributes" ( "user", "attributeKey", "attribute" ) VALUES ( $1, $2, $3 )', [ userId, keyId, attributeId ], callback, con);
	});
}

exports.User = User;
exports.createUser = createUser;
exports.getUser = getUser;
exports.encodePassword = encodePassword;
exports.checkPassword = checkPassword;

exports.identityIsInKeyring = identityIsInKeyring;
exports.attributeIsInKeyring = attributeIsInKeyring;
exports.addIdentityToKeyring = addIdentityToKeyring;
exports.addAttributeToKeyring = addAttributeToKeyring;