var pgp = require("node-pgp");
var pgpBasic = require("./pgpBasic");
var i18n = require("./i18n");

function _basicChecks(keyID, signatureInfo, callback)
{
	if(!signatureInfo.issuer || !signatureInfo.date)
		callback(new i18n.Error("Signatures without issuer or date information are unacceptable."));
	else
		callback(null);
}

/**
 * Verifies that a key signature has been made by the given issuer.
 * 
 * @param keyID {String} The ID of the key being signed
 * @param keyBinary {Buffer} The body of the key being signed
 * @param signatureInfo {Object} info object as returned by pgp.packetContent.getSignaturePacketInfo()
 * @param callback {Function} function(err, verified), where verified can be a boolean or null if the issuer key was not found
 * @param con {Object|null} A database connection
*/

function verifyKeySignature(keyID, keyBinary, signatureInfo, callback, con) {
	_basicChecks(keyId, signatureInfo, function(err) {
		if(err) { callback(err); return; }
		
		pgBasic.getKey(signatureInfo.issuer, function(err, issuerInfo) {
			if(err) { callback(err); return; }
			if(issuerInfo == null) { callback(null, null); return; }
			
			if(signatureInfo.sigtype == pg.consts.SIG.SUBKEY)
				pgp.signing.verifySubkeySignature(issuerInfo.binary, keyBinary, signatureInfo.binary, issuerInfo.binary, handleVerified);
			else
				pgp.signing.verifyKeySignature(keyBinary, signatureInfo.binary, issuerInfo.binary, handleVerified);
			
			function handleVerified(err, verified)
			{
				if(err) { callback(err); return; }
				if(!verified) { callback(null, false); return; }
				
				if(sigInfo.sigtype == pgp.consts.SIG.KEY_REVOK || sigInfo.sigtype == pgp.consts.SIG.SUBKEY_REVOK)
				{
					
				}
			}
		}, con);
	});
}

function _checkRevokationStatus(keyId, callback, con) {
	var authorisedKeys = [ ];
	
	pgpBasic.fifoQuery('SELECT upper(to_hex("issuer")), "sigtype" FROM "keys_signatures" WHERE "key" = $1 AND "sigtype" IN ($2, $3) AND "verified" = true \
		UNION SELECT "issuer", "sigtype" FROM "keys_identities_signatures" WHERE "key" = $1 AND "sigtype" IN ($2, $3) AND "verified" = true \
		UNION SELECT "issuer", "sigtype" FROM "keys_attributes_signatures" WHERE "key" = $1 AND "sigtype" IN ($2, $3) AND " verified" = true',
		[ pgpBasic.encodeKeyId(keyId), pgp.consts.SIG.REVOK, pgp.consts.SIG.SUBKEY_REVOK ],
		function(err, sigRecords) {
			if(err) { callback(err); return; }
			
			next();

			// Walk through each revocation signature and check whether the issuer is authorised
			function next() {
				sigRecords.next(function(err, sigRecord) {
					if(err)
						callback(err);
					else if(!sigRecord)
						callback(null, false);
					else if(sigRecord.sigtype == pgp.consts.SIG.SUBKEY_REVOK)
					{ // If this is a subkey revokation, check the parent key(s) and see if any of them authorises the issuer of the revocation
						pgpBasic.getParentKeys(keyId, function(err, parentKeyIds) {
							if(err) { callback(err); return; }
							
							var i = 0;
							checkParentKey();
							function checkParentKey() {
								if(i >= parentKeyIds.length)
									next(); // None of the parents authorises the issuer, so continue with the next revocation signature
								else
									check(sigRecord.issuer, sigRecord.id, parentKeyIds[i++], checkParentKey);
							}
						});
					}
					else // If this is a key revokation, check if the key itself authorises the issuer of the revocation
						check(sigRecord.issuer, sigRecord.id, keyId, next);
				});
			}
		}, con
	);
	
	// Check if the parent key authorises the issuer key to make a revocation signature
	// If it does, call revoke(), if it does not, call cb, in case of an error, call callback(err)
	function check(issuerId, signatureId, parentKeyId,  cb) {
		if(sigRecord.issuer == parentKeyId)
			revoke();
		else
		{
			pgpBasic.getKey(issuerId, function(err, issuerRecord) {
				if(err) { callback(err); return; }
				
				pgp.packetContent.getPublicKeyPacketInfo(issuerRecord.binary, function(err, issuerInfo) {
					if(err) { callback(err); return; }
					
					_isAuthorisedRevoker(parentKeyId, issuerInfo, function(err, authorised) {
						if(err)
							callback(err);
						else if(authorised)
							revoke(signatureId);
						else
							cb();
					}, con);
				});
			}, con);
		}
	}
	
	// Revoke the key
	function revoke(signatureId) {
		pgpBasic.query('UPDATE "keys" SET "revoked" = $1 WHERE "id" = $2', [ signatureId, pgpBasic.encodeKeyId(keyId) ], function(err) {
			if(err)
				callback(err);
			else
				callback(null, true);
	}
}

function _isAuthorisedRevoker(keyId, issuerKeyInfo, callback, con) {
	pgpBasic.fifoQuery('SELECT "binary" FROM "keys_signatures" WHERE "key" = $1 AND "sigtype" = $2 AND "verified" = true \
		UNION SELECT "binary" FROM "keys_identities_signatures" WHERE "key" = $1 AND "sigtype" IN ($3, $4, $5, $6) AND "verified" = true \
		UNION SELECT "binary" FROM "keys_attributes_signatures" WHERE "key" = $1 AND "sigtype" IN ($3, $4, $5, $6 AND "verified" = true',
		[ pgpBasic.encodeKeyId(keyId), pgp.consts.SIG.KEY, pgp.consts.SIG.CERT_0, pgp.consts.SIG_CERT_1, pgp.consts.SIG_CERT_2, pgp.consts.SIG_CERT_3 ],
		function(err, fifo) {
			if(err) { callback(err); return; }

			next();
			function next() {
				fifo.next(function(err, sigRecord) {
					if(err) { callback(err); return; }
					
					pgp.packetContent.getSignaturePacketInfo(sigRecord.binary, function(err, info) {
						if(err)
							callback(err);
						else if(info == null)
							callback(null, false);
						else if(info.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY] && info.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY] == issuerKeyInfo.fingerprint)
							callback(null, true);
						else
							next();
					});
				});
			}
		}, con
	);
}


/**
 * Verifies that a subkey signature has been made by the given issuer.
 * 
 * @param key {Buffer|String} The parent key body or ID
 * @param subkey {Buffer|String} The subkey body or ID
 * @param issuer {Buffer|String} The issuer key body or ID
 * @param signature {Buffer} The signature body
 * @param callback {Function} function(err, verified), where verified can be a boolean or null if the issuer key was not found
 * @param con {Object|null} A database connection
*/

function verifySubkeySignature(signatureInfo, callback, con) {
	_getObjectsForVerifying(signatureInfo.key, signatureInfo.issuer, signatureInfo.subkey, pgpBasic.getSubkey, callback, con, function(key, issuer, subkey) {
		pgp.signing.verifySubkeySignature(key, subkey, signatureInfo.binary, issuer, callback);
	});
}


/**
 * Verifies that an identity signature has been made by the given issuer.
 * 
 * @param key {Buffer|String} The parent key body or ID
 * @param identity {Buffer|String} The identity
 * @param issuer {Buffer|String} The issuer key body or ID
 * @param signature {Buffer} The signature body
 * @param callback {Function} function(err, verified), where verified can be a boolean or null if the issuer key was not found
 * @param con {Object|null} A database connection
*/

function verifyIdentitySignature(signatureInfo, callback, con) {
	_getObjectsForVerifying(signatureInfo., issuer, null, null, callback, con, function(key, issuer, identity) {
		pgp.signing.verifyIdentitySignature(key, new Buffer(identity, "utf8"), signature, issuer, callback);
	});
}


/**
 * Verifies that an attribute signature has been made by the given issuer.
 * 
 * @param key {Buffer|String} The parent key body or ID
 * @param attribute {Buffer|String} The attribute body or ID
 * @param issuer {Buffer|String} The issuer key body or ID
 * @param signature {Buffer} The signature body
 * @param callback {Function} function(err, verified), where verified can be a boolean or null if the issuer key was not found
 * @param con {Object|null} A database connection
*/

function verifyAttributeSignature(key, attribute, issuer, signature, callback, con) {
	_getObjectsForVerifying(key, issuer, subkey, pgpBasic.getAttribute, callback, con, function(key, issuer, attribute) {
		pgp.signing.verifyAttributeSignature(key, subkey, signature, issuer, callback);
	});
}



function verifySignaturesMadeByKey(keyInfo) {
	
}

exports.verifyKeySignature = verifyKeySignature;
exports.verifySubkeySignature = verifySubkeySignature;
exports.verifyIdentitySignature = verifyIdentitySignature;
exports.verifyAttributeSignature = verifyAttributeSignature;
