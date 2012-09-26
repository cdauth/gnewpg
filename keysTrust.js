var pgp = require("node-pgp");
var i18n = require("./i18n");
var db = require("./database");

/*
 * These are the security relations that need to be calculated:
 * 1. Verify all kinds of signatures. For this, the signed key (plus the signed subkey, identity or attribute) and the issuer key need to be available.
 *    The signed key can be assumed to be available as else the signature wouldn't be there. This check needs to be done in the following cases:
 *     a) A signature is added. Verify it if the issuer key is available.
 *     b) A public key is added. Verify all unverified signatures issued by this key.
 * 2. Check if a key has been revoked. For this, it needs to be checked whether the key contains validated key revocation signatures. These are valid
 *    if the signature has been issued by the key itself, or it has been issued by a key whose fingerprint is set in a key or certification signature
 *    that contains a hashed sub-packet of the type SIGSUBPKT.REV_KEY. The revocation or expiration status of such a signature is irrelevant, as that
 *    would make revoking a revocation possible, which is not intended. This check needs to be done in the following cases:
 *     a) a revocation signature is verified by check 1. The key is revoked if the issuer is authorised.
 *     b) a key or certification signature is verified that contains a revocation key authorisation. Check 2a is re-run on all revocation signatures of the key.
 * 3. Check if a subkey has been revoked. This is the case if the key contains (verified) subkey revocation signatures. A subkey revocation signature is
 *    valid if it has been issued by a key that has also signed the key with a subkey binding signature ("parent key"), or by a key that has been authorised
 *    by the parent key to make revocations for it as described in check 2. A subkey revocation signature only revokes the subkey binding signature, not
 *    the key itself! (As that would make it possible for anyone to revoke a key by just signing it with a subkey binding signature.) This check needs
 *    to be done in the following cases:
 *     a) a subkey revocation signature is verified by check 1. The subkey binding signature is revoked if the issuer is authorised.
 *     b) a subkey binding signature is verified by check 1. Check 3a is rerun on all subkey revocation signatures of the key.
 *     c) a key or certification signature is verified that contains a revocation key authorisation. All subkey revocation signatures of all keys that
 *        contain a subkey binding signature of this key are checked again by check 3a.
 * 4. Check if a key or certification signature has been revoked. This is the case if the same key, identity or attribute contains a verified signature
 *    of the type SIG.CERT_REVOKE. Such a signature is valid if it has been issued by the same key that issued the signature that is being revoked, [or
 *    by a key that is authorised by that key to make revocations for it (as described in check 2)]. [A signature revocation signature may contain the hash
 *    of the signature it revokes in the SIGSUBPKT.SIGTARGET sub-packet, in that case it only revokes that specific signature.] Else it revokes all signatures
 *    issued by the same key on the same object on a date earlier than that of the revocation signature. SIGSUBPKT.REVOCABLE can prevent signatures
 *    from being revoked. This check needs to be done when:
 *     a) a signature revocation signature is verified. If the issuer is authorised and the signature being revoked are available, the revocation is performed
 *     b) any key or certification signature is _uploaded_. Search all verified signature revocation signatures if they revoke it.
 *     [c) a key or certification signature is verified that contains a revocation key authorisation. All signatures that have been made by this key need
 *        to be checked by check 4b.]
 * 5. Check the expiration date of a key. v3 keys contain an expiration date themselves, this is the default value. It can be overridden by making
 *    a v4 self-signature with the expiration date set in the SIGSUBPKT.KEY_EXPIRE sub-packet. The self-signature with the newest date that specifies
 *    a key expiration date is the relevant one. Subkey binding signatures can also contain a key expiration date. As we do not store subkeys and
 *    keys separately, in our database, we will set the expiration date of _all_ subkey binding signatures for the subkey by the same key to the
 *    key expiration date specified in the newest one of them (instead of setting the expiration date of the subkey itself). This check needs to be
 *    performed when:
 *     a) a self-signature is verified (check 1) that sets a key expiration date.
 *     b) a subkey binding signature is verified
 * 6. Check the primary identity of a key. This is set by the SIGSUBPKT.PRIMARY_UID subpacket in a self-signature of an identity. The one from the
 *    most recent self-signature counts. This check needs to be performed when:
 *     a) a self-signature is verified (check 1) that sets the primary ID.
 * 7. TODO: Check if there are any signatures that contain the sub packet consts.SIGSUBPKT.REV_KEY where the sensitive flag is set to true. These
 *    signatures may only be made public if there is a revocation signature by the key specified there.
 *     a) a signature with such a sensitive sub-packet is _uploaded_. If there are no revocation signatures issued by the specified authorised revoker on
 *        the key itself, its subkeys, its identities and its attributes, mark the signature as sensitive.
 *     b) a key is revoked by check 2 or 3 [or 4]. Check if the revoker has been authorised using a sensitive revocation authorisation signature, if so
 *        mark it as non-sensitive.
*/

function _handleVerifiedSignature(keyId, sigInfo, callback, con)
{
	var checks = [ ];
	var i = 0;
	var nextCheck = function(err) {
		if(err)
			callback(err);
		else if(i >= checks.length)
			callback(null);
		else
			checks[i++]();
	};

	// Check 2a, 3a
	if(sigInfo.sigtype == pgp.consts.SIG.KEY_REVOK || sigInfo.sigtype == pgp.consts.SIG.SUBKEY_REVOK)
		checks.push(function() { _checkRevocationStatus(keyId, nextCheck); });
	// Check 2b, 3c
	else if([ pgp.consts.SIG.KEY, pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ].indexOf(sigInfo.sigtype) != -1 && sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY])
	{
		checks.push(function() { _checkRevocationStatus(keyId, nextCheck, con); });
		checks.push(function() {
			db.getEntries("keys_subkeys", [ "id" ], { "parentkey" : keyId }, function(subkeyRecords) {
				if(err) { callback(err); return; }
				
				next();
				function next() {
					subkeyRecords.next(function(err, subkeyRecord) {
						if(err === true)
							nextCheck();
						else if(err)
							nextCheck(err);
						else
							_checkRevocationStatus(subkeyRecord.id, next, con);
					});
				}
			}, con);
		});
	}
	// Check 3b
	else if(sigInfo.sigtype == pgp.consts.SUBKEY)
		checks.push(function() { _checkRevocationStatus(keyId, nextCheck, con); });

	if([ pgp.consts.SIG.KEY, pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3, pgp.consts.SIG.CERT_REVOK, pgp.consts.SIG.KEY_BY_SUBKEY ].indexOf(sigInfo.sigtype) != -1)
	{
		// Check 4a, 4b
		checks.push(function() { _checkSignatureRevocationStatus(keyId, nextCheck, con); });
		
		// Check 5a, 6a
		if(sigInfo.issuer == keyId && (sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE] || sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.PRIMARY_UID]))
			checks.push(function() { _checkSelfSignatures(keyId, nextCheck, con); });
	}
	
	// Check 5b
	if(sigInfo.sigtype == pgp.consts.SIG.SUBKEY && sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE])
		checks.push(function() { _checkSubkeyExpiration(keyId, sigInfo.issuer, nextCheck, con); });
	
	nextCheck();
}

function _checkRevocationStatus(keyId, callback, con) {
	var authorisedKeys = [ ];
	
	db.getEntries("keys_signatures", [ "id", "issuer", "sigtype" ], { "key" : keyId, "sigtype": [ pgp.consts.SIG.REVOK, pgp.consts.SIG.SUBKEY_REVOK ], "verified" : true }, function(err, sigRecords) {
		if(err) { callback(err); return; }
		
		next();

		// Walk through each revocation signature and check whether the issuer is authorised
		function next() {
			sigRecords.next(function(err, sigRecord) {
				if(err === true)
					callback(null);
				else if(err)
					callback(err);
				else if(sigRecord.sigtype == pgp.consts.SIG.SUBKEY_REVOK)
				{ // If this is a subkey revokation, check the parent key(s) and see if any of them authorises the issuer of the revocation
					db.getEntries("keys_subkeys", [ "parentkey" ], { id: keyId }, function(err, subkeyRecords) {
						if(err) { callback(err); return; }
						
						checkParentKey();
						function checkParentKey() {
							subkeyRecords.next(function(err, subkeyRecord) {
								if(err === true)
									next(); // None of the parents authorises the issuer, so continue with the next revocation signature
								else if(err)
									callback(err);
								else
									check(sigRecord.issuer, sigRecord.id, subkeyRecord.parentkey, checkParentKey, true);
							});
						}
					}, con);
				}
				else // If this is a key revokation, check if the key itself authorises the issuer of the revocation
					check(sigRecord.issuer, sigRecord.id, keyId, next, false);
			});
		}
	}, con);
	
	// Check if the parent key authorises the issuer key to make a revocation signature
	// If it does, call revoke(), if it does not, call cb, in case of an error, call callback(err)
	function check(issuerId, signatureId, parentKeyId, cb, isSubkey) {
		if(sigRecord.issuer == parentKeyId)
			revoke();
		else
		{
			db.getEntry("keys", [ "binary" ], { id: issuerId }, function(err, issuerRecord) {
				if(err) { callback(err); return; }
				
				pgp.packetContent.getPublicKeyPacketInfo(issuerRecord.binary, function(err, issuerInfo) {
					if(err) { callback(err); return; }
					
					_isAuthorisedRevoker(parentKeyId, issuerInfo, function(err, authorised) {
						if(err)
							callback(err);
						else if(authorised)
							revoke(signatureId, isSubkey, issuerId);
						else
							cb();
					}, con);
				});
			}, con);
		}
	}
	
	// Revoke the key
	function revoke(signatureId, isSubkey, issuerId) {
		if(isSubkey) // Check 3: revoke the subkey binding signatures
			db.update("keys_signatures", { revokedby: signatureId }, { sigtype: pgp.consts.SIG.SUBKEY, key: keyId, issuer: issuerId }, callback, con);
		else // Check 2: revoke the key
			db.update("keys", { revokedby: signatureId }, { id: keyId }, callback, con);
	}
}

function _isAuthorisedRevoker(keyId, issuerKeyInfo, callback, con) {
	db.getEntries("keys_signatures_all", [ "binary" ], { key: keyId, sigtype : [ pgp.consts.SIG.KEY, pgp.consts.SIG.CERT_0, pgp.consts.SIG_CERT_1, pgp.consts.SIG_CERT_2, pgp.consts.SIG_CERT_3 ]}, function(err, fifo) {
		if(err) { callback(err); return; }

		next();
		function next() {
			fifo.next(function(err, sigRecord) {
				if(err === true) { callback(null, false); }
				if(err) { callback(err); return; }
				
				pgp.packetContent.getSignaturePacketInfo(sigRecord.binary, function(err, info) {
					if(err) { callback(err); return; }
					
					var authorised = false;
					if(info.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY])
					{
						for(var i=0; i<info.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY].length; i++)
						{
							if(info.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY][i].value == issuerKeyInfo.fingerprint)
							{
								authorised = true;
								break;
							}
						}
					}
					if(authorised)
						callback(null, true);
					else
						next();
				});
			});
		}
	}, con);
}

// Check 4: Find verified revocation signatures on the specified key and its sub-objects and revoke all earlier signatures by the same issuer on the same object
function _checkSignatureRevocationStatus(keyId, callback, con) {
	// Select all signatures that are issued on the same object by the same issuer earlier than a revocation signature
	var query = '\
	SELECT "sigs"."id" AS "id", "sigs"."binary" AS "binary", "revs"."id" AS "revokedby", \'keys_signatures\' AS "table" \
		FROM \
			( SELECT "id", "key", "issuer", "date", "binary" FROM "keys_signatures" WHERE "sigtype" IN ( $2, $3 ) AND "verified" = true ) AS "sigs", \
			( SELECT "id", "key", "issuer", "date" FROM "keys_signatures" WHERE "sigtype" = $4 AND "key" = $1 AND "verified" = true ORDER BY date ASC ) AS "revs" \
		WHERE "sigs"."key" = "revs"."key" AND "sigs"."issuer" = "revs"."issuer" AND "sigs"."date" <= "revs"."date" \
	UNION SELECT "sigs"."id" AS "id", "sigs"."binary" AS "binary", "revs"."id" AS "revokedby", \'keys_identities_signatures\' AS "table" \
		FROM \
			( SELECT "id", "identity", "key", "issuer", "date", "binary" FROM "keys_identities_signatures" WHERE "sigtype" IN ( $5, $6, $7, $8 ) AND "verified" = true ) AS "sigs", \
			( SELECT "id", "identity", "key", "issuer", "date" FROM "keys_identities_signatures" WHERE "sigtype" = $4 AND "key" = $1 AND "verified" = true ORDER BY date ASC ) AS "revs" \
		WHERE "sigs"."key" = "revs"."key" AND "sigs"."identity" = "revs"."identity" AND "sigs"."issuer" = "revs"."issuer" AND "sigs"."date" <= "revs"."date" \
	UNION SELECT "sigs"."id" AS "id", "sigs"."binary" AS "binary", "revs"."id" AS "revokedby", \'keys_attributes_signatures\' AS "table" \
		FROM \
			( SELECT "id", "attribute", "key", "issuer", "date", "binary" FROM "keys_attributes_signatures" WHERE "sigtype" IN ( $5, $6, $7, $8 ) AND "verified" = true ) AS "sigs", \
			( SELECT "id", "attribute", "key", "issuer", "date" FROM "keys_attributes_signatures" WHERE "sigtype" = $4 AND "key" = $1 AND "verified" = true ORDER BY date ASC ) AS "revs" \
		WHERE "sigs"."key" = "revs"."key" AND "sigs"."attribute" = "revs"."attribute" AND "sigs"."issuer" = "revs"."issuer" AND "sigs"."date" <= "revs"."date";';
	
	db.fifoQuery(query, [ keyId, pgp.consts.SIG.KEY, pgp.consts.SIG.KEY_BY_SUBKEY, pgp.consts.SIG.CERT_REVOK, pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ], function(err, sigRecords) {
		if(err) { callback(err); return; }

		next();
		function next() {
			sigRecords.next(function(err, sigRecord) {
				if(err === true) { callback(null); return; }
				if(err) { callback(err); return; }
				
				pgp.packetContent.getSignaturePacketInfo(sigRecord.binary, function(err, sigInfo) {
					if(err) { callback(err); return; }

					if(!sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REVOCABLE] || !sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REVOCABLE][0].value)
					{
						db.update(sigRecord.table, { revokedby: sigRecord.revokedby }, { id: sigRecord.id }, function(err) {
							if(err) { callback(err); return; }
							
							next();
						}, con);
					}
					else
						next();
				});
			});
		}
	}, con);
}

// Check 5a, 6: Check self-signatures for expiration date and primary id
function _checkSelfSignatures(keyId, callback, con) {
	db.getEntry("keys", [ "binary" ], { id: keyId }, function(err, keyRecord) {
		if(err) { callback(err); return; }

		pgp.packetContent.getPublicKeyPacketInfo(keyRecord.binary, function(err, keyInfo) {
			if(err) { callback(err); return; }

			db.getEntries("keys_signatures_all", [ "id", "binary", "table" ], { key: keyId, issuer: keyId, verified: true, sigtype: [ pgp.consts.SIG.KEY, pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ], revokedby: null }, 'ORDER BY "date" ASC', function(err, sigRecords) {
				if(err) { callback(err); return; }
				
				var expire = keyInfo.expires;
				var primary = null;
				
				next();
				function next() {
					sigRecords.next(function(err, sigRecord) {
						if(err === true) { end(); return; }
						if(err) { callback(err); return; }
						
						pgp.packetContent.getSignaturePacketInfo(sigRecord.binary, function(err, sigInfo) {
							if(err) { callback(err); return; }
							
							if(sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE])
								expire = new Date(keyInfo.date.getTime() + sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE][0].value*1000);
							if(sigRecord.table == "keys_identities_signatures" && sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.PRIMARY_UID] && sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.PRIMARY_UID][0].value)
								primary = sigRecord.id;
							
							next();
						});
					});
				}
				
				function end() {
					var updates = { };
					if(expire == null || expire == 0)
						updates.expires = null;
					else
						updates.expires = expire;
					
					if(primary != null)
					{
						db.getEntry("keys_signatures", [ "identity" ], { id: primary }, function(err, sigRecord) {
							if(err) { callback(err); return; }
							
							updates.primary_identity = sigRecord.identity;
							update();
						}, con);
					}
					else
					{
						updates.primary_identity = null;
						update();
					}
					
					function update() {
						db.update("keys", updates, { id: keyId }, callback, con);
					}
				}
			}, con);
		});
	}, con);
}

function _checkSubkeyExpiration(keyId, parentId, callback, con) {
	db.getEntry("keys", [ "binary" ], { id: keyId }, function(err, keyRecord) {
		if(err) { callback(err); return; }
		
		pgp.packetContent.getPublicKeyPacketInfo(keyRecord.binary, function(err, keyInfo) {
			if(err) { callback(err); return; }
			
			db.getEntries("keys_signatures", [ "date", "binary" ], { key: keyId, issuer: parentId, verified: true, sigtype: pgp.consts.SIG.SUBKEY }, 'ORDER BY "date" ASC', function(err, sigRecords) {
				if(err) { callback(err); return; }
				
				var expire = keyInfo.expires;
				
				next();
				function next() {
					sigRecords.next(function(err, sigRecord) {
						if(err === true) { end(); return; }
						else if(err) { callback(err); return; }
						
						pgp.packetContent.getSignaturePacketInfo(sigRecord.binary, function(err, sigInfo) {
							if(err) { callback(err); return; }
							
							if(sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE])
								expire = new Date(keyInfo.date.getTime() + sigInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE].value*1000);
							next();
						});
					});
				}
				
				function end() {
					db.update("keys_signatures", { expires: expire }, { key: keyId, issuer: parentId, sigtype: pgp.consts.SIG.SUBKEY }, callback, con);
				}
			}, con);
		});
	}, con);
}

/**
 * Verifies that a key or subkey signature has been made by the given issuer. Fetches the issuer information from the database, but does not
 * write the verified status to the database.
 * 
 * @param signatureId {String}
 * @param callback {Function} function(err, verified), where verified can be a boolean or null if the issuer key was not found
 * @param con {pg.Connection|null} A database connection
*/

function verifyKeySignature(signatureId, callback, con) {
	db.getEntry("keys_signatures", [ "key", "issuer", "sigtype", "binary" ], { id: signatureId }, function(err, sigRecord) {
		if(err) { callback(err); return; }

		db.getEntry("keys", [ "binary" ], { id: sigRecord.key }, function(err, keyRecord) {
			if(err) { callback(err); return; }
			
			if(sigRecord.key == sigRecord.issuer)
				getIssuer(null, keyRecord);
			else
				db.getEntry("keys", [ "binary" ], { id: sigRecord.issuer }, getIssuer, con);
			
			function getIssuer(err, issuerRecord) {
				if(err) { callback(err); return; }
				if(issuerRecord == null) { callback(null, null); }
				
				if(sigRecord.sigtype == pgp.consts.SIG.SUBKEY || sigRecord.sigtype == pgp.consts.SIG.SUBKEY_REVOK)
					pgp.signing.verifySubkeySignature(issuerRecord.binary, keyRecord.binary, sigRecord.binary, issuerRecord.binary, verifyCallback);
				else
					pgp.signing.verifyKeySignature(keyRecord.binary, sigRecord.binary, issuerRecord.binary, verifyCallback);

				function verifyCallback(err, verified) {
					if(err)
						callback(err);
					else if(!verified)
					{
						db.delete("keys_signatures", { id: signatureId }, function(err) {
							if(err) { callback(err); return; }
							
							callback(null, false);
						}, con);
					}
					else
					{
						pgp.packetContent.getSignaturePacketInfo(sigRecord.binary, function(err, sigInfo) {
							if(err) { callback(err); return; }

							_handleVerifiedSignature(sigRecord.key, sigInfo, function(err) {
								if(err) { callback(err); return; }
								
								db.update("keys_signatures", { verified: true }, { id: signatureId }, function(err) {
									if(err) { callback(err); return; }
									callback(null, true);
								}, con);
							}, con);
						});
					}
				}
			}
		}, con);
	}, con);
}


/**
 * Verifies that an identity signature has been made by the given issuer. Fetches the issuer information from the database, but does not
 * write the verified status to the database.
 * 
 * @param signatureId {String}
 * @param callback {Function} function(err, verified), where verified can be a boolean or null if the issuer key was not found
 * @param con {pg.Connection|null} A database connection
*/

function verifyIdentitySignature(signatureId, callback, con) {
	db.getEntry("keys_identities_signatures", [ "key", "identity", "issuer", "binary" ], { id: signatureId }, function(err, sigRecord) {
		if(err) { callback(err); return; }

		db.getEntry("keys", [ "binary" ], { id: sigRecord.key }, function(err, keyRecord) {
			if(err) { callback(err); return; }
			
			if(sigRecord.key == sigRecord.issuer)
				getIssuer(null, keyRecord);
			else
				db.getEntry("keys", [ "binary" ], { id: sigRecord.issuer }, getIssuer, con);
			
			function getIssuer(err, issuerRecord) {
				if(err) { callback(err); return; }
				if(issuerRecord == null) { callback(null, null); return; }
					
				pgp.signing.verifyIdentitySignature(keyRecord.binary, new Buffer(sigRecord.identity, "utf8"), sigRecord.binary, issuerRecord.binary, function(err, verified) {
					if(err)
						callback(err);
					else if(!verified)
					{
						db.delete("keys_identities_signatures", { id: signatureId }, function(err) {
							if(err) { callback(err); return; }
							
							callback(null, false);
						}, con);
					}
					else
					{
						pgp.packetContent.getSignaturePacketInfo(sigRecord.binary, function(err, sigInfo) {
							if(err) { callback(err); return; }

							_handleVerifiedSignature(sigRecord.key, sigInfo, function(err) {
								if(err) { callback(err); return; }
								
								db.update("keys_identities_signatures", { verified: true }, { id: signatureId }, function(err) {
									if(err) { callback(err); return; }
									callback(null, true);
								}, con);
							}, con);
						});
					}
				});
			}
		}, con);
	}, con);
}


/**
 * Verifies that an identity signature has been made by the given issuer. Fetches the issuer information from the database, but does not
 * write the verified status to the database.
 * 
 * @param signatureId {String}
 * @param callback {Function} function(err, verified), where verified can be a boolean or null if the issuer key was not found
 * @param con {pg.Connection|null} A database connection
*/

function verifyAttributeSignature(signatureId, callback, con) {
	db.getEntry("keys_attributes_signatures", [ "key", "attribute", "issuer", "binary" ], { id: signatureId }, function(err, sigRecord) {
		if(err) { callback(err); return; }
		
		db.getEntry("keys", [ "binary" ], { id: sigRecord.key }, function(err, keyRecord) {
			if(err) { callback(err); return; }
			
			db.getEntry("keys_attributes", [ "binary" ], { id: sigRecord.attribute, key: sigRecord.key }, function(err, attributeRecord) {
				if(err) { callback(err); return; }
			
				if(sigRecord.key == sigRecord.issuer)
					getIssuer(null, keyRecord);
				else
					db.getEntry("keys", [ "binary" ], { id: sigRecord.issuer }, getIssuer, con);
				
				function getIssuer(err, issuerRecord) {
					if(err) { callback(err); return; }
					if(issuerRecord == null) { callback(null, null); return; }
						
					pgp.signing.verifyAttributeSignature(keyRecord.binary, attributeRecord.binary, sigRecord.binary, issuerRecord.binary, function(err, verified) {
						if(err)
							callback(err);
						else if(!verified)
						{
							db.delete("keys_attributes_signatures", { id: signatureId }, function(err) {
								if(err) { callback(err); return; }
								
								callback(null, false);
							}, con);
						}
						else
						{
							pgp.packetContent.getSignaturePacketInfo(sigRecord.binary, function(err, sigInfo) {
								if(err) { callback(err); return; }

								_handleVerifiedSignature(sigRecord.key, sigInfo, function(err) {
									if(err) { callback(err); return; }
									
									db.update("keys_attributes_signatures", { verified: true }, { id: signatureId }, function(err) {
										if(err) { callback(err); return; }
										callback(null, true);
									}, con);
								}, con);
							});
						}
					});
				}
			}, con);
		}, con);
	}, con);
}


/**
 * Verifies all unverified signatures made by the given key. Writes the verified status to the database.
 * 
 * @param keyId {String} The ID of the key
 * @param callback {Function} function(err)
 * @param con {pg.Connection|null) A database connection
*/

function handleKeyUpload(keyId, callback, con) {
	db.getEntries("keys_signatures_all", [ "id", "table" ], { issuer: keyId, verified: false }, function(err, sigRecords) {
		if(err) { callback(err); return; }
		
		next();
		function next() {
			sigRecords.next(function(err, sigRecord) {
				if(err === true) { callback(null); return; }
				else if(err) { callback(err); return; }
				
				if(sigRecord.table == "keys_identities_signatures")
					verifyIdentitySignature(sigRecord.id, next, con);
				else if(sigRecord.table == "keys_attributes_signatures")
					verifyIdentitySignature(sigRecord.id, next, con);
				else
					verifyKeySignature(sigRecord.id, next, con);
			});
		}
	}, con);
}

exports.verifyKeySignature = verifyKeySignature;
exports.verifyIdentitySignature = verifyIdentitySignature;
exports.verifyAttributeSignature = verifyAttributeSignature;
exports.handleKeyUpload = handleKeyUpload;