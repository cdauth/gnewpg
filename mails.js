var pgp = require("node-pgp");
var config = require("./config");
var fs = require("fs");
var utils = require("./utils");
var db = require("./database");
var async = require("async");
var keyrings = require("./keyrings");
var keys = require("./keys");
var mailcomposer = require("mailcomposer");

var privateKey;

function loadPrivateKey(callback) {
	pgp.formats.decodeKeyFormat(fs.createReadStream(config.notificationPrivateKey)).readUntilEnd(function(err, notificationPrivateKey) {
		if(err) { callback(err); return; }

		privateKey = notificationPrivateKey;
		
		console.log("Testing private notification key...");
		pgp.signing.detachedSignText("test", privateKey, function(err, ret) {
			if(err)
				callback(err);
			else if(ret.length == 0)
				callback(new Error("Signing failed."));
			else
			{
				console.log("Success.");
				callback(null);
			}
		});
	});
}

function sendEncryptedMail(text, keyId, callback) {
	async.waterfall([
		function(cb) {
			keys.getPrimaryId(keyId, keyrings.getUniversalKeyring(), function(err, primaryIdRecord) {
				if(err)
					return cb(err);
				
				if(primaryIdRecord.email && utils.isEmailAddress(primaryIdRecord.email))
					return cb(null, primaryIdRecord.id);
				
				db.fifoQuerySync('SELECT "id","email" FROM "keys_identities_selfsigned" WHERE "key" = $1 AND "email" IS NOT NULL AND "expires" > $2 AND "revokedby" IS NULL AND "email_blacklisted" = FALSE', [ keyId, new Date() ]).forEachSeries(function(idRecord, cb2) {
					if(utils.isEmailAddress(idRecord.email))
						cb(null, idRecord.id);
					else
						cb2();
				}, function(err) {
					callback(err, new i18n.Error_("This key does not contain any valid e-mail addresses."));
				});
			});
		},
		function(id, cb) {
			var composer = new mailcomposer.MailComposer();
	
			var boundary = "gnewpg-"+utils.generateRandomString(44);
			
			_encryptTo(messageText, toKeyId, function(err, encrypted) {
				if(err)
					return callback(err);
				
				pgp.formats.enarmor(encrypted, pgp.consts.ARMORED_MESSAGE.MESSAGE).readUntilEnd(function(err, armored) {
					if(err)
						return callback(err);

					var encryptedMessage = "Content-Type: multipart/encrypted;\r\n" +
						" protocol=\"application/pgp-encrypted\";\r\n" +
						" boundary=\""+boundary+"\"\r\n" +
						"\r\n" +
						"--"+boundary+"\r\n" +
						"Content-Type: application/gpg-encrypted\r\n" +
						"\r\n" +
						"Version: 1\r\n" +
						"\r\n" +
						"--"+boundary+"\r\n" +
						"Content-Type: application/octet-stream\r\n" +
						"\r\n" +
						armored + // Contains newline at end
						"\r\n" +
						"--"+boundary;
					
					callback(null, encryptedMessage);
				});
			});
		}
	], callback);
	
	function to() {
	

function _encryptTo(text, toKeyId, callback) {
	keys.exportKey(toKeyId, keyrings.getUniversalKeyring(), { attributes: [ ] }).readUntilEnd(function(err, key) {
		if(err)
			return callback(err);
		
		pgp.encryption.encryptData(text, key, toKeyId, callback);
	});
}


function _signMessage(messageText, callback) {
	var signedPart = "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n";
	signedPart += mimelib.encodeQuotedPrintable(messageText);

	pgp.signing.detachedSignText(signedPart, privateKey, function(err, signature) {
		if(err)
			return callback(err);
		
		pgp.formats.enarmor(signature, pgp.consts.ARMORED_MESSAGE.MESSAGE).readUntilEnd(function(err, armored) {
			if(err)
				return callback(err);
			
			var boundary = "gnewpg-"+utils.generateRandomString(44);
			
			var signedMessage = "Content-Type: multipart/signed;\r\n" +
				" boundary=\""+boundary+"\";\r\n" +
				" micalg=pgp-sha256;\r\n" +
				" protocol=\"application/pgp-signature\"\r\n" +
				"\r\n" +
				"--"+boundary+"\r\n" +
				signedPart+"\r\n" +
				"--"+boundary+"\r\n" +
				"Content-Type: application/pgp-signature\r\n" +
				"\r\n" +
				armored + // Contains newline at end
				"\r\n" +
				"--"+boundary+"--";
			
			callback(message);
		});
	});
}

function _encryptMessage(messageText, toKeyId, callback) {
	var boundary = "gnewpg-"+utils.generateRandomString(44);
	
	_encryptTo(messageText, toKeyId, function(err, encrypted) {
		if(err)
			return callback(err);
		
		pgp.formats.enarmor(encrypted, pgp.consts.ARMORED_MESSAGE.MESSAGE).readUntilEnd(function(err, armored) {
			if(err)
				return callback(err);

			var encryptedMessage = "Content-Type: multipart/encrypted;\r\n" +
				" protocol=\"application/pgp-encrypted\";\r\n" +
				" boundary=\""+boundary+"\"\r\n" +
				"\r\n" +
				"--"+boundary+"\r\n" +
				"Content-Type: application/gpg-encrypted\r\n" +
				"\r\n" +
				"Version: 1\r\n" +
				"\r\n" +
				"--"+boundary+"\r\n" +
				"Content-Type: application/octet-stream\r\n" +
				"\r\n" +
				armored + // Contains newline at end
				"\r\n" +
				"--"+boundary;
			
			callback(null, encryptedMessage);
		});
	});
}

exports.loadPrivateKey = loadPrivateKey;