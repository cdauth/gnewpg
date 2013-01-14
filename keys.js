var pgp = require("node-pgp");
var db = require("./database");
var keyrings = require("./keyrings");
var async = require("async");
var i18n = require("./i18n");

function getKeyWithSubobjects(keyring, keyId, detailed, callback) {
	var keyFields = [ "id", "fingerprint", "security", "date", "expires", "revoked" ].concat(detailed ? [ "versionSecurity", "version", "pkalgo", "sizeSecurity", "size" ] : [ ]);
	var signatureFields = [ "id", "expires", "revoked", "security", "sigtype", "verified", "issuer", "date" ].concat(detailed ? [ "version", "hashalgoSecurity", "hashalgo", "hashedSubPackets" ] : [ ]);
	var subkeyFields = [ "id", "revoked", "expires", "security" ].concat(detailed ? [ "versionSecurity", "version", "sizeSecurity", "size", "pkalgo" ] : [ ]);
	var identityFields = [ "id", "revoked", "expires", "security" ];
	var attributeFields = [ "id", "revoked", "expires", "security", "subPackets" ];

	keyring.getKey(keyId, function(err, keyInfo) {
		if(err)
			return callback(err);
		if(keyInfo == null)
			return callback(new i18n.Error_("Key %s not found.", keyId));

		keyInfo.signatures = [ ];
		keyInfo.subkeys = [ ];
		keyInfo.identities = [ ];
		keyInfo.attributes = [ ];

		async.series([
			function(next) {
				resolveRevokedBy(keyInfo, next);
			},
			function(next) {
				handleSignatures(keyInfo, keyring.getKeySignatures(keyId, null, signatureFields), next);
			},
			function(next) {
				keyring.getSelfSignedSubkeys(keyId, null, subkeyFields).forEachSeries(function(subkeyInfo, next) {
					keyInfo.subkeys.push(subkeyInfo);

					resolveRevokedBy(subkeyInfo, function(err) {
						if(err)
							return next(err);

						handleSignatures(subkeyInfo, keyring.getSubkeySignatures(keyId, subkeyInfo.id), next);
					});
				}, next);
			},
			function(next) {
				keyring.getSelfSignedIdentities(keyId, null, identityFields).forEachSeries(function(identityInfo, next) {
					keyInfo.identities.push(identityInfo);

					resolveRevokedBy(identityInfo, function(err) {
						if(err)
							return next(err);

						handleSignatures(identityInfo, keyring.getIdentitySignatures(keyId, identityInfo.id), next);
					});
				}, next);
			},
			function(next) {
				keyring.getSelfSignedAttributes(keyId, null, attributeFields).forEachSeries(function(attributeInfo, next) {
					keyInfo.attributes.push(attributeInfo);

					resolveRevokedBy(attributeInfo, function(err) {
						if(err)
							return next(err);

						handleSignatures(attributeInfo, keyring.getAttributeSignatures(keyId, attributeInfo.id), next);
					});
				}, next);
			}
		], function(err) {
			callback(err, keyInfo);
		});
	}, keyFields);

	function handleSignatures(objInfo, signatures, callback) {
		if(!objInfo.signatures)
			objInfo.signatures = [ ];

		signatures.forEachSeries(function(signatureInfo, next) {
			resolveIssuer(signatureInfo, function(err) {
				if(err)
					return next(err);

				resolveRevokedBy(signatureInfo, function(err) {
					if(err)
						return next(err);

					objInfo.signatures.push(signatureInfo);
					next();
				});
			});
		}, callback);
	}

	function resolveIssuer(signatureInfo, callback) {
		keyring.getKey(signatureInfo.issuer, function(err, keyInfo) {
			if(err || keyInfo == null)
				return callback(err);

			keyInfo.expired = (keyInfo.expires && keyInfo.expires.getTime() <= (new Date()).getTime());
			signatureInfo.issuerRecord = keyInfo;

			keyring.getPrimaryIdentity(signatureInfo.issuer, function(err, identityInfo) {
				if(err || identityInfo == null)
					return callback(err);

				keyInfo.primary_identity = identityInfo.id;
				callback();
			}, [ "id" ]);
		}, [ "revoked", "expires" ])
	}
	
	function resolveRevokedBy(objInfo, callback) {
		objInfo.expired = (objInfo.expires && objInfo.expires.getTime() <= (new Date()).getTime());

		if(!objInfo.revoked)
			return callback();

		keyring.getSignatureById(objInfo.revoked, function(err, signatureInfo) {
			if(err || signatureInfo == null)
				return callback(err);

			objInfo.revokedby = signatureInfo;

			resolveIssuer(objInfo.revokedby, callback);
		}, [ "date", "verified", "issuer" ]);
	}
}

exports.getKeyWithSubobjects = getKeyWithSubobjects;