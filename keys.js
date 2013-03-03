var pgp = require("node-pgp");
var db = require("./database");
var async = require("async");
var i18n = require("./i18n");
var utils = require("./utils");

function getKeyWithSubobjects(keyring, keyId, detailed, callback) {
	var keyFields = [ "id", "fingerprint", "security", "date", "expires", "revoked" ].concat(detailed == 2 ? [ "versionSecurity", "version", "pkalgo", "sizeSecurity", "size" ] : [ ]);
	var signatureFields = [ "id", "expires", "revoked", "security", "sigtype", "verified", "issuer", "date" ].concat(detailed == 2 ? [ "version", "hashalgoSecurity", "hashalgo", "hashedSubPackets" ] : [ ]);
	var subkeyFields = [ "id", "revoked", "expires", "security" ].concat(detailed == 2 ? [ "versionSecurity", "version", "sizeSecurity", "size", "pkalgo" ] : [ ]);
	var identityFields = [ "id", "name", "email", "comment", "revoked", "expires", "security" ];
	var attributeFields = [ "id", "revoked", "expires", "subPackets" ];

	keyring.getKey(keyId, function(err, keyInfo) {
		if(err)
			return callback(err);
		if(keyInfo == null)
			return callback(null, null);

		keyInfo.signatures = [ ];
		keyInfo.subkeys = [ ];
		keyInfo.identities = [ ];
		keyInfo.attributes = [ ];

		async.series([
			function(next) {
				keyring.getPrimaryIdentity(keyId, function(err, identityInfo) {
					if(err)
						return next(err);

					keyInfo.primary_identity = identityInfo.id;
					next();
				}, [ "id" ]);
			},
			function(next) {
				resolveRevokedBy(keyInfo, next);
			},
			function(next) {
				if(detailed >= 1)
					handleSignatures(keyInfo, keyring.getKeySignatures(keyId, null, signatureFields), next);
				else
					next();
			},
			function(next) {
				keyring.getSelfSignedSubkeys(keyId, null, subkeyFields).forEachSeries(function(subkeyInfo, next) {
					keyInfo.subkeys.push(subkeyInfo);

					resolveRevokedBy(subkeyInfo, function(err) {
						if(err)
							return next(err);

						if(detailed >= 1)
							handleSignatures(subkeyInfo, keyring.getSubkeySignatures(keyId, subkeyInfo.id), next);
						else
							next();
					});
				}, next);
			},
			function(next) {
				keyring.getSelfSignedIdentities(keyId, null, identityFields).forEachSeries(function(identityInfo, next) {
					keyInfo.identities.push(identityInfo);

					resolveRevokedBy(identityInfo, function(err) {
						if(err)
							return next(err);

						if(detailed >= 1)
							handleSignatures(identityInfo, keyring.getIdentitySignatures(keyId, identityInfo.id), next);
						else
							next();
					});
				}, next);
			},
			function(next) {
				keyring.getSelfSignedAttributes(keyId, null, attributeFields).forEachSeries(function(attributeInfo, next) {
					keyInfo.attributes.push(attributeInfo);

					resolveRevokedBy(attributeInfo, function(err) {
						if(err)
							return next(err);

						if(detailed >= 1)
							handleSignatures(attributeInfo, keyring.getAttributeSignatures(keyId, attributeInfo.id), next);
						else
							next();
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

function resolveKeyList(keyring, list) {
	return list.map(function(keyId, cb) {
		keyring.getKey(keyId, function(err, keyInfo) {
			if(err)
				return cb(err);

			keyInfo.expired = (keyInfo.expires && keyInfo.expires.getTime() <= (new Date()).getTime());

			keyring.getPrimaryIdentity(keyId, function(err, identityInfo) {
				keyInfo.primary_identity = identityInfo.id;

				/*getKeySettings(keyring._con, keyId, function(err, keySettings) {
					if(err)
						return cb(err);

					keyInfo.user = keySettings.user;*/

					cb(null, keyInfo);
				/*});*/
			}, [ "id" ]);
		}, [ "id", "revoked", "expires" ]);
	});
}

function getKeysOfUser(con, userId) {
	return db.getEntries(con, "keys_settings", [ "key" ], { user: userId }).map(function(it, next) {
		next(null, it.key);
	});
}

function getKeySettings(con, keyId, callback, fields) {
	db.getEntry(con, "keys_settings", fields || "*", { key: keyId }, function(err, settings) {
		if(err)
			return callback(err);

		callback(null, settings || { key: keyId });
	});
}

function updateKeySettings(con, keyId, fields, callback) {
	db.entryExists(con, "keys_settings", { key: keyId }, function(err, exists) {
		if(err)
			return callback(err);

		if(exists)
			db.update(con, "keys_settings", fields, { key: keyId }, callback);
		else
			db.insert(con, "keys_settings", utils.extend({ key: keyId }, fields), callback);
	});
}

function getIdentitySettings(con, keyId, identityId, callback, fields) {
	db.getEntry(con, "keys_identities_settings", fields || "*", { key: keyId, id: identityId }, function(err, settings) {
		if(err)
			return callback(err);

		callback(null, settings || { key: keyId, id: identityId });
	});
}

function updateIdentitySettings(con, keyId, identityId, fields, callback) {
	db.entryExists(con, "keys_identities_settings", { key: keyId, id: identityId }, function(err, exists) {
		if(err)
			return callback(err);

		if(exists)
			db.update(con, "keys_identities_settings", fields, { key: keyId, id: identityId }, callback);
		else
			db.insert(con, "keys_identities_settings", utils.extend({ key: keyId, id: identityId }, fields), callback);
	});
}

function getAttributeSettings(con, keyId, attributeId, callback, fields) {
	db.getEntry(con, "keys_attributes_settings", fields || "*", { key: keyId, id: attributeId }, function(err, settings) {
		if(err)
			return callback(err);

		callback(null, settings || { key: keyId, id: attributeId });
	});
}

function updateAttributeSettings(con, keyId, attributeId, fields, callback) {
	db.entryExists(con, "keys_attributes_settings", { key: keyId, id: attributeId }, function(err, exists) {
		if(err)
			return callback(err);

		if(exists)
			db.update(con, "keys_attributes_settings", fields, { key: keyId, id: attributeId }, callback);
		else
			db.insert(con, "keys_attributes_settings", utils.extend({ key: keyId, id: attributeId }, fields), callback);
	});
}

exports.getKeyWithSubobjects = getKeyWithSubobjects;
exports.resolveKeyList = resolveKeyList;
exports.getKeysOfUser = getKeysOfUser;
exports.getKeySettings = getKeySettings;
exports.updateKeySettings = updateKeySettings;
exports.getIdentitySettings = getIdentitySettings;
exports.updateIdentitySettings = updateIdentitySettings;
exports.getAttributeSettings = getAttributeSettings;
exports.updateAttributeSettings = updateAttributeSettings;