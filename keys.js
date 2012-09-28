var pgp = require("node-pgp");
var db = require("./database");
var keyrings = require("./keyrings");
var async = require("async");
var i18n = require("./i18n");

function removeEmptyKey(keyId, callback, con) {
	db.entryExists("keys_signatures", { key: keyId }, function(err, exists) {
		if(err) callback(err);
		else if(exists) callback(null, false);
		else
		{
			db.entryExists("keys_identities", { key: keyId }, function(err, exists) {
				if(err) callback(err);
				else if(exists) callback(null, false);
				else
				{
					db.entryExists("keys_attributes", { key: keyId }, function(err, exists) {
						if(err) callback(err);
						else if(exists) callback(null, false);
						else
						{
							db.delete("keys", { id: keyId }, function(err) {
								if(err)
									callback(err);
								else
									callback(null, true);
							}, con);
						}
					}, con);
				}
			}, con);
		}
	}, con);
}

function removeEmptyIdentity(keyId, id, callback, con) {
	db.entryExists("keys_identities_signatures", { key: keyId, identity: id }, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null, false);
		else
		{
			db.delete("keys_identities", { key: keyId, id: id }, function(err) {
				if(err)
					callback(err);
				else
					callback(null, true);
			}, con);
		}
	}, con);
}

function removeEmptyAttribute(keyId, attrId, callback, con) {
	db.entryExists("keys_attributes_signatures", { key: keyId, attribute: attrId }, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null, false);
		else
		{
			db.delete("keys_attributes", { key: keyId, attribute: attrId }, function(err) {
				if(err)
					callback(err);
				else
					callback(null, true);
			}, con);
		}
	}, con);
}

function getPrimaryIdentity(keyId, keyring, callback, con) {
	db.getEntry("keys", [ "primary_identity" ], { id: keyId }, function(err, keyRecord) {
		if(err) { callback(err); return; }
		else if(keyRecord == null) { callback(null, null); return; }
		
		if(keyRecord.primary_identity != null)
		{
			db.getEntry("identities", "*", { key: keyId, id: keyRecord.primary_identity }, function(err, primaryRecord) {
				if(err) { callback(err); return; }
				
				if(primaryRecord.perm_public)
					callback(null, primaryRecord);
				else
				{
					keyrings.keyringContainsIdentity(keyring, keyId, primaryId, function(err, contains) {
						if(err) { callback(err); return; }
						
						if(contains)
							callback(null, primaryRecord);
						else
							findOther();
					}, false, con);
				}
			}, con);
		}
		else
			findOther();
		
		function findOther() {
			db.getEntries("keys_identities_selfsigned", "*", { key: keyId }, function(err, identityRecords) {
				if(err) { callback(err); return; }
				
				next();
				function next() {
					identityRecords.next(function(err, identityRecord) {
						if(err === true) { callback(null, null); return; }
						else if(err) { callback(err); return; }
						
						if(identityRecord.perm_public)
							callback(null, identityRecord);
						else
						{
							keyrings.keyringContainsIdentity(keyring, keyId, identityRecord.id, function(err, contains) {
								if(err) { callback(err); return; }
								
								if(contains)
									callback(null, identityRecord);
								else
									next();
							}, false, con);
						}
					});
				}
			});
		}
	}, con);
}

function exportKey(keyId, keyring, selection, con) {
	var ret = new pgp.BufferedStream();
	
	db.getEntry("keys", [ "binary", "perm_idsearch" ], { id: keyId }, function(err, keyRecord) {
		if(err) { ret._endData(err); return; }
		else if(keyRecord == null) { ret._endData(new i18n.Error_("Key %s does not exist.", keyId)); return; }
		
		async.series([
			function(cb) {
				if(keyRecord.perm_idsearch)
					cb();
				else if(keyring)
				{
					keyrings.keyringContainsKey(keyring, keyId, function(err, contains) {
						if(err)
							cb(err);
						else if(contains)
							cb();
						else
							cb(new i18n.Error_("No permission to view key %s.", keyId));
					}, con);
				}
				else
					cb(new i18n.Error_("No permission to view key %s.", keyId));
			},
			function(cb) {
				ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.PUBLIC_KEY, keyRecord.binary));
				
				db.getEntriesSync("keys_signatures", [ "id", "binary" ], { key: keyId, sigtype: [ pgp.consts.SIG.KEY_BY_SUBKEY, pgp.consts.SIG.KEY, pgp.consts.SIG.KEY_REVOK ] }, con).forEachSeries(function(signatureRecord, cb2) {
					if(!selection || !selection.signatures || selection.signatures[signatureRecord.id] != false)
						ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.SIGNATURE, signatureRecord.binary));
					cb2();
				}, cb);
			},
			function(cb) {
				db.getEntriesSync("keys_subkeys", [ "id", "binary" ], { parentkey: keyId }, con).forEachSeries(function(subkeyRecord, cb2) {
					if(!selection || !selection.subkeys || selection.subkeys[subkeyRecord.id] != false)
					{
						ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.PUBLIC_SUBKEY, subkeyRecord.binary));
						
						db.getEntriesSync("keys_signatures", [ "binary" ], { key: subkeyRecord.id, sigtype: [ pgp.consts.SIG.SUBKEY, pgp.consts.SIG.SUBKEY_REVOK ] }, con).forEachSeries(function(signatureRecord, cb3) {
							if(!selection || !selection.signatures || selection.signatures[signatureRecord.id] != false)
								ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.SIGNATURE, signatureRecord.binary));
							cb3();
						}, cb2);
					}
					else
						cb2();
				}, cb);
			},
			function(cb) {
				db.getEntriesSync("keys_identities_selfsigned", [ "id", "perm_public" ], { key: keyId }, con).forEachSeries(function(identityRecord, cb2) {
					if(selection && selection.identities && selection.identities[identityRecord.id] == false)
						send(null, false);
					if(identityRecord.perm_public)
						send(null, true);
					else if(keyring)
						keyrings.keyringContainsIdentity(keyring, keyId, identityRecord.id, send, con);
					else
						send(null, false);

					function send(err, perm) {
						if(err)
							cb2(err);
						else if(!perm)
							cb2();
						else
						{
							ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.USER_ID, new Buffer(identityRecord.id, "utf8")));
							
							db.getEntriesSync("keys_identities_signatures", [ "binary" ], { key: keyId, identity: identityRecord.id }, con).forEachSeries(function(signatureRecord, cb3) {
								if(!selection || !selection.signatures || selection.signatures[signatureRecord.id] != false)
									ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.SIGNATURE, signatureRecord.binary));
								cb3();
							}, cb2);
						}
					}
				}, cb);
			},
			function(cb) {
				db.getEntriesSync("keys_attributes_selfsigned", [ "id", "binary", "perm_public" ], { key: keyId }, con).forEachSeries(function(attributeRecord, cb2) {
					if(selection && selection.attributes && selection.attributes[attributeRecord.id] == false)
						send(null, false);
					else if(attributeRecord.perm_public)
						send(null, true);
					else if(keyring)
						keyrings.keyringContainsAttribute(keyring, keyId, attributeRecord.id, send, con);
					else
						send(null, false);

					function send(err, perm) {
						if(err)
							cb2(err);
						else if(!perm)
							cb2();
						else
						{
							ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.ATTRIBUTE, attributeRecord.binary));
							
							db.getEntriesSync("keys_attributes_signatures", [ "binary" ], { key: keyId, attribute: attributeRecord.id }, con).forEachSeries(function(attributeRecord, cb3) {
								if(!selection || !selection.signatures || selection.signatures[signatureRecord.id] != false)
									ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.SIGNATURE, attributeRecord.binary));
								cb3();
							}, cb2);
						}
					}
				}, cb);
			}
		], function(err) {
			ret._endData(err);
		});
	}, con);
	
	return ret;
}

function getKeyWithSubobjects(keyId, keyring, detailed, callback, con) {
	db.getEntry("keys", "*", { id: keyId }, function(err, keyRecord) {
		if(err) { callback(err); return; }
		if(keyRecord == null) { callback(new i18n.Error_("Key %s not found.", keyId)); return; }
		
		keyRecord.signatures = [ ];
		keyRecord.subkeys = [ ];
		keyRecord.identities = [ ];
		keyRecord.attributes = [ ];
		
		async.series([
			function(cb) { // Check if key is public or in keyring
				if(keyRecord.perm_public)
					cb();
				else if(keyring)
				{
					keyrings.keyringContainsKey(keyring, keyId, function(err, contains) {
						if(err)
							cb(err);
						else if(contains)
							cb();
						else
							cb(new i18n.Error_("No permission to view key %s.", keyId));
					});
				}
				else
					cb(new i18n.Error_("No permission to view key %s.", keyId));
			},
			function(cb) { // If detailed, add key packet info
				if(!detailed)
					cb();
				else
				{
					pgp.packetContent.getPublicKeyPacketInfo(keyRecord.binary, function(err, keyInfo) {
						if(err)
							cb(err);
						else
						{
							keyRecord.info = keyInfo;
							cb();
						}
					});
				}
			},
			function(cb) { // Add key signatures
				handleSignatures(db.getEntriesSync("keys_signatures", "*", { key: keyId, sigtype: [ pgp.consts.SIG.KEY_BY_SUBKEY, pgp.consts.SIG.KEY, pgp.consts.SIG.KEY_REVOK ] }, 'ORDER BY "date" ASC', con), keyRecord, cb);
			},
			function(cb) { // Add subkeys and their signatures
				db.getEntriesSync("keys_subkeys", "*", { parentkey: keyId }, con).forEachSeries(function(subkeyRecord, cb2) {
					keyRecord.subkeys.push(subkeyRecord);
					handleSignatures(db.getEntriesSync("keys_signatures", "*", { key: subkeyRecord.id, sigtype: [ pgp.consts.SIG.SUBKEY, pgp.consts.SIG.SUBKEY_REVOK ] }, 'ORDER BY "date" ASC', con), subkeyRecord, function(err) {
						if(err || !detailed)
							cb2(err);
						else
						{
							pgp.packetContent.getPublicSubkeyPacketInfo(subkeyRecord.binary, function(err, subkeyInfo) {
								if(err)
									cb2(err);
								else
								{
									subkeyRecord.info = subkeyInfo;
									cb2();
								}
							});
						}
					});
				}, cb);
			},
			function(cb) { // Add identities and their signatures
				db.getEntriesSync("keys_identities_selfsigned", "*", { key: keyId }, con).forEachSeries(function(identityRecord, cb2) {
					async.series([
						function(cb3) { // Check if identity is public or in keyring
							if(identityRecord.perm_public)
								cb3();
							else if(keyring)
							{
								keyrings.keyringContainsIdentity(keyring, keyId, identityRecord.id, function(err, contains) {
									if(err || contains)
										cb3(err);
									else
										cb2(); // Skip identity
								});
							}
							else
								cb2(); // Skip identity
						},
						function(cb3) { // Add details
							keyRecord.identities.push(identityRecord);

							if(!detailed)
								cb3();
							else
							{
								pgp.packetContent.getIdentityPacketInfo(identityRecord.id, function(err, identityInfo) {
									if(err)
										cb3(err);
									else
									{
										identityRecord.info = identityInfo;
										cb3();
									}
								});
							}
						},
						function(cb3) { // Add signatures
							handleSignatures(db.getEntriesSync("keys_identities_signatures", "*", { key: keyId, identity: identityRecord.id }, 'ORDER BY "date" ASC', con), identityRecord, cb3);
						}
					], cb2);
				}, cb);
			},
			function(cb) { // Add attributes and their signatures
				db.getEntriesSync("keys_attributes_selfsigned", "*", { key: keyId }, con).forEachSeries(function(attributeRecord, cb2) {
					async.series([
						function(cb3) { // Check if attribute is public or in keyring
							if(attributeRecord.perm_public)
								cb3();
							else if(keyring)
							{
								keyrings.keyringContainsAttribute(keyring, keyId, attributeRecord.id, function(err, contains) {
									if(err || contains)
										cb3(err);
									else
										cb2(); // Skip attribute
								});
							}
							else
								cb2(); // Skip attribute
						},
						function(cb3) { // Add details
							keyRecord.attributes.push(attributeRecord);

							if(!detailed)
								cb3();
							else
							{
								pgp.packetContent.getAttributePacketInfo(attributeRecord.binary, function(err, attributeInfo) {
									if(err)
										cb3(err);
									else
									{
										attributeRecord.info = attributeInfo;
										cb3();
									}
								});
							}
						},
						function(cb3) { // Add signatures
							handleSignatures(db.getEntriesSync("keys_attributes_signatures", "*", { key: keyId, attribute: attributeRecord.id }, 'ORDER BY "date" ASC', con), attributeRecord, cb3);
						}
					], cb2);
				}, cb);
			}
		], function(err) {
			if(err)
				callback(err);
			else
				callback(null, keyRecord);
		});
	}, con);
	
	function handleSignatures(signatureRecords, objRecord, callback) {
		if(!objRecord.signatures)
			objRecord.signatures = [ ];

		handleRevokedBy(objRecord, function(err) {
			if(err) { callback(err); return; }

			signatureRecords.forEachSeries(function(signatureRecord, cb) {
				objRecord.signatures.push(signatureRecord);
				
				async.waterfall([
					async.apply(addPrimaryId, signatureRecord),
					async.apply(handleRevokedBy, signatureRecord),
					function(cb2) {
						if(detailed)
							pgp.packetContent.getSignaturePacketInfo(signatureRecord.binary, cb2);
						else
							cb2(null, null);
					},
					function(signatureInfo, cb2) {
						if(signatureInfo)
							signatureRecord.info = signatureInfo;
						cb2();
					}
				], cb);
			}, callback);
		});
	};
	
	function addPrimaryId(signatureRecord, callback) {
		getPrimaryIdentity(signatureRecord.issuer, keyring, function(err, primaryIdRecord) {
			if(err) { callback(err); return }
			
			if(primaryIdRecord)
				signatureRecord.issuer_primary_identity = primaryIdRecord.id;
			callback(null);
		}, con);
	}
	
	function handleRevokedBy(objRecord, callback) {
		objRecord.expired = (objRecord.expires && objRecord.expires.getTime() <= (new Date()).getTime());

		if(!objRecord.revokedby)
			callback();
		else
		{
			async.waterfall([
				function(cb) {
					db.getEntry("keys_signatures_all", "*", { id: objRecord.revokedby }, cb, con);
				},
				function(signatureRecord, cb) {
					objRecord.revokedby = signatureRecord;
					addPrimaryId(signatureRecord, cb);
				},
				function(cb) {
					if(!detailed)
						cb(null, null);
					else
						pgp.packetContent.getSignaturePacketInfo(objRecord.revokedby.binary, cb);
				},
				function(signatureInfo, cb) {
					if(signatureInfo)
						objRecord.revokedby.info = signatureInfo;
					cb();
				}
			], callback);
		}
	}
}

exports.removeEmptyKey = removeEmptyKey;
exports.removeEmptyIdentity = removeEmptyIdentity;
exports.removeEmptyAttribute = removeEmptyAttribute;
exports.getPrimaryIdentity = getPrimaryIdentity;
exports.exportKey = exportKey;
exports.getKeyWithSubobjects = getKeyWithSubobjects;