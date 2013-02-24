var Mail = require("node-pgp-mail");
var keyrings = require("./keyrings");
var config = require("./config");
var db = require("./database");

//var privateKey;
var mailer = null;

function loadPrivateKey(callback) {
	db.getConnection(function(err, con) {
		if(err)
			return callback(err);

		exports.mailer = mailer = new Mail(new keyrings.UnfilteredKeyring(con), config.mailTransport, config.mailTransportOptions);

		//sendEncryptedMail("9C22F455A0CD27E9", "Test", "Test message", callback);

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

function sendEncryptedMail(toKeyId, subject, text, callback) {
	mailer.getMailRecipient(toKeyId, function(err, id) {
		if(err)
			return callback(err);
		if(id == null)
			return callback(new i18n.Error_("This key does not contain any valid e-mail addresses."));

		mailer.sendEncryptedMail(id, subject, text, toKeyId, callback);
	})
}

exports.loadPrivateKey = loadPrivateKey;
exports.mailer = mailer;
exports.sendEncryptedMail = sendEncryptedMail;