var Mail = require("node-pgp-mail");
var keyrings = require("./keyrings");
var config = require("./config");
var db = require("./database");
var i18n = require("./i18n");
var utils = require("./utils");
var keys = require("./keys");
var pgp = require("node-pgp");

//var privateKey;
var con = null;
var keyring = null;
var mailer = null;

function loadPrivateKey(callback) {
	db.getConnection(function(err, con_) {
		if(err)
			return callback(err);

		con = con_;
		keyring = new keyrings.UnfilteredKeyring(con);
		mailer = new Mail(keyring, config.mailTransport, config.mailTransportOptions);

		//sendEncryptedMail("9C22F455A0CD27E9", "Test", "Test message", callback);

		setInterval(cleanInactiveTokens, config.tokenTimeout*100);

		callback(null);
	});

	/*pgp.formats.decodeKeyFormat(fs.createReadStream(config.notificationPrivateKey)).readUntilEnd(function(err, notificationPrivateKey) {
		if(err) { callback(err); return; }

		privateKey = notificationPrivateKey;

		console.log("Testing private notification key...");
		pgp.signing.detachedSignText("test", privateKey, function(err, ret) {
			if(err)
				callback(err);
			else
			{
				console.log("Success.");
				callback(null);
			}
		});
	});*/
}

function sendEncryptedMail(toKeyId, subject, text, callback, acceptRevoked) {
	mailer.getMailRecipient(toKeyId, function(err, id) {
		if(err)
			return callback(err);
		if(id == null)
			return callback(new i18n.Error_("This key does not contain any valid e-mail addresses."));

		mailer.sendEncryptedMail(id, subject, text, toKeyId, callback, { From: config.notificationFrom }, acceptRevoked);
	});
}

function sendVerificationMail(keyId, user, callback) {
	var token = pgp.utils.generateRandomString(43);
	db.insert(con, "users_ownership_verification", { token: token, user: user.id, key: keyId, date: new Date() }, function(err) {
		if(err)
			return callback(err);

		sendEncryptedMail(keyId, i18n.gettext("gnewpg ownership verification for key %s", user.locale, utils.formatKeyId(keyId)), i18n.gettext("[ownership_mail keyId=%s username=%s link=%s]", user.locale, utils.formatKeyId(keyId), user.id, config.baseurl+"/claimkey/"+encodeURIComponent(keyId)+"?token="+encodeURIComponent(token)), callback, true);
	});
}

function verifyVerificationMail(keyId, user, token, callback) {
	db.entryExists(con, "users_ownership_verification", { token: token, user: user.id, key: keyId }, function(err, exists) {
		if(err)
			return callback(err);

		if(!exists)
			return callback(null, false);

		db.remove(con, "users_ownership_verification", { key: keyId }, function(err) {
			if(err)
				return callback(err);

			keys.updateKeySettings(con, keyId, { user: user.id }, function(err) {
				if(err)
					return callback(err);

				callback(null, true);
			});
		});
	});
}

function cleanInactiveTokens() {
	con.query('DELETE FROM "users_ownership_verification" WHERE $1 - "date" > $2', [ new Date(), config.tokenTimeout ], function(err) {
		if(err)
			console.warn("Error cleaning inactive tokens", err);
	});
}

exports.loadPrivateKey = loadPrivateKey;
exports.sendVerificationMail = sendVerificationMail;
exports.sendEncryptedMail = sendEncryptedMail;
exports.verifyVerificationMail = verifyVerificationMail;