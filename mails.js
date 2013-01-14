var pgp = require("node-pgp");
var config = require("./config.json");
var fs = require("fs");
var utils = require("./utils");
var db = require("./database");
var async = require("async");
var keyrings = require("./keyrings");
var keys = require("./keys");
var mailcomposer = require("mailcomposer");
var mimelib = require("mimelib");
var Mime = require("./mailsMime");
var nodemailer = require("nodemailer");

var privateKey;
var transport;

function loadPrivateKey(callback) {
	transport = nodemailer.createTransport(config.mailTransport, config.mailTransportOptions);

	pgp.formats.decodeKeyFormat(fs.createReadStream(config.notificationPrivateKey)).readUntilEnd(function(err, notificationPrivateKey) {
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
	});
}

function getMailRecipient(keyId, callback) {
	async.waterfall([
		async.apply(keys.getPrimaryId, keyId, keyrings.getUniversalKeyring()),
		function(primaryIdRecord, cb) {
			if(primaryIdRecord.email && utils.isEmailAddress(primaryIdRecord.email))
				cb(primaryIdRecord.email);
			else
			{
				db.fifoQuerySync('SELECT "id","email" FROM "keys_identities_selfsigned" WHERE "key" = $1 AND "email" IS NOT NULL AND "expires" > $2 AND "revokedby" IS NULL AND "email_blacklisted" = FALSE', [ keyId, new Date() ]).forEachSeries(function(idRecord, cb2) {
					if(utils.isEmailAddress(idRecord.email))
						cb(null, idRecord.id);
					else
						cb2();
				}, function(err) {
					cb(err || new i18n.Error_("This key does not contain any valid e-mail addresses."));
				});
			}
		}
	], callback);
}

function sendSignedMail(to, subject, text, callback) {
	async.waterfall([
		async.apply(_signMessage, text),
		async.apply(_sendMail)
	], callback);
}

function sendSignedAndEncryptedMail(toKeyId, subject, text, callback) {
	async.auto({
		recipient: async.apply(getMailRecipient, toKeyId),
		sign: async.apply(_signMessage, text),
		encrypt: [ "sign", function(cb, res) { _encryptMessage(res.sign.toString(), toKeyId, cb); } ],
		send: [ "recipient", "encrypt", function(cb, res) { _sendMail(res.recipient, subject, res.encrypt, cb); } ]
	}, callback);
}

function _sendMail(to, subject, mime, callback) {
	mime.headers["To"] = to;
	mime.headers["Subject"] = subject;
	mime.headers["Mime-Version"] = "1.0";

	var composer = new mailcomposer.MailComposer();
	composer.streamMessage = function() {
		this.emit("data", new Buffer(mime.toString(), "utf8"));
		this.emit("end");
	};
	transport.sendMailWithTransport(composer, callback);
}

function _encryptTo(text, toKeyId, callback) {
	keys.exportKey(toKeyId, keyrings.getUniversalKeyring(), { attributes: [ ] }).readUntilEnd(function(err, key) {
		if(err)
			return callback(err);
		
		pgp.encryption.encryptData(text, key, toKeyId, callback);
	});
}


function _signMessage(messageText, callback) {
	var signedPart = new Mime("text/plain; charset=utf-8", messageText, { }, "quoted-printable");

	pgp.signing.detachedSignText(signedPart.toString(), privateKey, function(err, signature) {
		if(err)
			return callback(err);
		
		pgp.formats.enarmor(signature, pgp.consts.ARMORED_MESSAGE.MESSAGE).readUntilEnd(function(err, armored) {
			if(err)
				return callback(err);

			var signedMessageMime = new Mime(
				"multipart/signed; micalg=pgp-sha256; protocol=\"application/pgp-signature\"",
				[
					signedPart,
					new Mime("application/pgp-signature", armored)
				]
			);

			callback(signedMessageMime);
		});
	});
}

function _encryptMessage(messageText, toKeyId, callback) {
	_encryptTo(messageText, toKeyId, function(err, encrypted) {
		if(err)
			return callback(err);
		
		pgp.formats.enarmor(encrypted, pgp.consts.ARMORED_MESSAGE.MESSAGE).readUntilEnd(function(err, armored) {
			if(err)
				return callback(err);

			var encryptedMessageMime = new Mime(
				"multipart/encrypted; protocol=\"application/pgp-encrypted\"",
				[
					new Mime("application/pgp-encrypted", "Version: 1"),
					new Mime("application/octet-stream", armored)
				]
			);
			
			callback(null, encryptedMessageMime);
		});
	});
}

exports.loadPrivateKey = loadPrivateKey;
exports.getMailRecipient = getMailRecipient;
exports.sendSignedMail = sendSignedMail;
exports.sendSignedAndEncryptedMail = sendSignedAndEncryptedMail;