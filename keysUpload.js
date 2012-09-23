var pgp = require("node-pgp");
var db = require("./database");
var keys = require("./keys");
var keysTrust = require("./keysTrust");
var users = require("./users");
var groups = require("./groups");
var i18n = require("./i18n");
var utils = require("./utils");

var intErr = new i18n.Error_("Internal error");

/**
 * Stores keys into the database.
 * @param key {Buffer|Readable Stream|String|pgp.BufferedStream} The key(s) in binary format.
 * @param callback {Function} Is run when the uploading has finished. Arguments: err
 * @param userId {String} The ID of a user to whose keyring to add the uploaded keys
 * @param groupId {String} The ID of a group to whose keyring to add the uploaded keys
*/
function uploadKey(key, callback, userId, groupId) {
	if(!(key instanceof pgp.BufferedStream))
		key = new pgp.BufferedStream(key);

	db.getConnection(function(err, con) {
		if(err) { callback(err); return; }

		con.query('BEGIN', [ ], function(err) {
			if(err) { callback(err, con); return; }

			var split = pgp.packets.splitPackets(pgp.formats.decodeKeyFormat(key));
			var uploaded = {
				uploadedKeys : [ ],
				failed : [ ]
			};
			
			var lastKey = null;
			var lastSubkey = null;
			var lastId = null;
			var lastAttr = null;
			
			// The according objects from uploaded.uploaded
			var lastKeyUpl = null;
			var lastSubkeyUpl = null;
			var lastIdUpl = null;
			var lastAttrUpl = null;
		
			readNextPacket();
			function readNextPacket() {
				split.next(function(err, type, header, body) {
					if(err)
					{
						if(err === true)
							end();
						else
							rollback(err);
						return;
					}
					
					pgp.packetContent.getPacketInfo(type, body, function(err, info) {
						if(err) { rollback(err); return; }

						var func = null;
						pktswitch: switch(info.pkt) {
							case pgp.consts.PKT.PUBLIC_KEY:
								var upl = { type: type, id: info.id, signatures: [ ], subkeys: [ ], identities: [ ], attributes: [ ] };
								_uploadKey(con, info, function(err) {
									if(err) {
										if(!(err instanceof i18n.Error_))
											console.warn("Error uploading key", (err instanceof i18n.Error_) ? err : err);
										uploaded.failed.push(utils.extend(upl, { err: intErr }));
										readNextPacket();
										return;
									}
									
									lastKey = info;
									lastKeyUpl = upl;
									lastSubkey = lastId = lastAttr = null;

									uploaded.uploadedKeys.push(lastKeyUpl);
									readNextPacket();
								});
								break;
							case pgp.consts.PKT.PUBLIC_SUBKEY:
								var upl = { type: type, id: info.id, signatures: [ ], subkeys: [ ], identities: [ ], attributes: [ ] };
								_uploadKey(con, info, function(err) {
									if(err) {
										if(!(err instanceof i18n.Error_))
											console.warn("Error uploading subkey", err);
										uploaded.failed.push(utils.extend(upl, { err: (err instanceof i18n.Error_) ? err : intErr }));
										readNextPacket();
										return;
									}
									
									lastSubkey = info;
									lastSubkeyUpl = upl;
									lastId = lastAttr = null;

									if(lastKey)
										lastKeyUpl.subkeys.push(lastSubkeyUpl);
									else
										uploaded.uploadedKeys.push(lastSubkeyUpl);
									readNextPacket();
								});
								break;
							case pgp.consts.PKT.USER_ID:
								var upl = { type: type, id: info.id, signatures: [ ] };

								if(lastKey == null) { uploaded.failed.push(utils.extend(upl, { err: new i18n.Error_("No associated key.") })); readNextPacket(); break; }
								
								_uploadIdentity(con, info, lastKey, function(err) {
									if(err) {
										if(!(err instanceof i18n.Error_))
											console.warn("Error uploading identity", err);
										uploaded.failed.push(utils.extend(upl, { err: (err instanceof i18n.Error_) ? err : intErr }));
										readNextPacket();
										return;
									}
									
									lastId = info;
									lastIdUpl = upl;
									lastSubkey = lastAttr = null;
									
									lastKeyUpl.identities.push(lastIdUpl);
									readNextPacket();
								});
								break;
							case pgp.consts.PKT.ATTRIBUTE:
								var upl = { type: type, id: info.id, signatures: [ ] };
								
								if(lastKey == null) { uploaded.failed.push(utils.extend(upl, { err: new i18n.Error_("No associated key.") })); readNextPacket(); break; }
								
								_uploadAttribute(con, info, lastKey, function(err) {
									if(err) {
										if(!(err instanceof i18n.Error_))
											console.warn("Error uploading attribute", err);
										uploaded.failed.push(utils.extend(upl, { err: (err instanceof i18n.Error_) ? err : intErr }));
										readNextPacket();
										return;
									}
									
									lastAttr = info;
									lastAttrUpl = upl;
									lastSubkey = lastId = null;
									
									lastKeyUpl.attributes.push(lastAttrUpl);
									readNextPacket();
								});
								break;
							case pgp.consts.PKT.SIGNATURE:
								var upl = { type: type, id: info.id, issuer: info.issuer, date: info.date, sigtype: info.sigtype };
								if(!info.issuer || !info.date)
								{
									uploaded.failed.push(utils.extend(upl, { err: new i18n.Error_("Signatures without issuer or date information are unacceptable.") }));
									readNextPacket();
									break;
								}
								if(!info.exportable)
								{
									uploaded.failed.push(utils.extend(upl, { err: new i18n.Error_("Signature is not exportable.") }));
									readNextPacket();
									break;
								}

								switch(info.sigtype)
								{
									case pgp.consts.SIG.CERT_0:
									case pgp.consts.SIG.CERT_1:
									case pgp.consts.SIG.CERT_2:
									case pgp.consts.SIG.CERT_3:
									case pgp.consts.SIG.CERT_REVOK:
										if(lastId == null && lastAttr == null)
										{
											uploaded.failed.push(utils.extend(upl, { err: new i18n.Error_("Signature type %s is only acceptable on identities and attributes.", "0x"+info.sigtype.toString(16)) }));
											readNextPacket();
											break pktswitch;
										}
										break;
									case pgp.consts.SIG.SUBKEY:
									case pgp.consts.SIG.SUBKEY_REVOK:
										if(lastSubkey == null)
										{
											uploaded.failed.push(utils.extend(upl, { err: new i18n.Error_("Signature type %s is only acceptable on subkeys.", "0x"+info.sigtype.toString(16)) }));
											readNextPacket();
											break pktswitch;
										}
										break;
									case pgp.consts.SIG.KEY:
									case pgp.consts.SIG.KEY_BY_SUBKEY:
									case pgp.consts.SIG.KEY_REVOK:
										lastSubkey = lastId = lastAttr = null;
										break;
									default:
										uploaded.failed.push(utils.extend(upl, { err: new i18n.Error_("Unsupported signature type %s.", "0x"+info.sigtype.toString(16)) }));
										readNextPacket();
										break pktswitch;
								}
								
								var func = null;
								var obj = null;
								var objUpl = null;

								if(lastSubkey != null)
								{
									func = _uploadKeySignature;
									obj = lastSubkey;
									objUpl = lastSubkeyUpl;
								}
								else if(lastId != null)
								{
									func = _uploadIdentitySignature;
									obj = lastId;
									objUpl = lastIdUpl;
								}
								else if(lastAttr != null)
								{
									func = _uploadAttributeSignature;
									obj = lastAttr;
									objUpl = lastAttrUpl;
								}
								else if(lastKey != null)
								{
									func = _uploadKeySignature;
									obj = lastKey;
									objUpl = lastKeyUpl;
								}
								else
								{
									uploaded.failed.push(utils.extend(upl, { err: new i18n.Error_("No associated object for signature.") }));
									readNextPacket();
									break;
								}
								
								func(con, info, obj, lastKey, function(err) {
									if(err) {
										if(!(err instanceof i18n.Error_))
											console.warn("Error uploading signature", err);
										uploaded.failed.push(utils.extend(upl, { err: (err instanceof i18n.Error_) ? err : intErr }));
										readNextPacket();
										return;
									}
									
									objUpl.signatures.push(upl);
									readNextPacket();
								});
								break;
							case pgp.consts.PKT.RING_TRUST:
								readNextPacket();
								break;
							default:
								uploaded.failed.push({ type: type, err: new i18n.Error_("Unknown packet type.") });
								readNextPacket();
						}
					});
				});
			}
			
			function rollback(err) {
				con.query('ROLLBACK', [ ], function(err2) {
					callback(err2 || err);
				});
			}
			
			function end() {
				loopKeys(0);
				function loopKeys(i) {
					if(i == uploaded.uploadedKeys.length)
					{
						con.query('COMMIT', [ ], function(err) {
							if(err)
								callback(err);
							else
								callback(null, uploaded);
						});
						return;
					}

					var it = uploaded.uploadedKeys[i];
					
					loopSubkeys(0);

					function loopSubkeys(j) {
						if(j == it.subkeys.length) { loopIdentities(0); return; }
						
						keys.removeEmptyKey(it.subkeys[j].id, function(err, removed) {
							if(err) { rollback(err); return; }

							if(removed)
							{
								uploaded.failed.push(utils.extend(it.subkeys[j], { err: new i18n.Error_("Subkey without signatures.") }));
								it.subkeys = it.subkeys.slice(0, j).concat(it.subkeys.slice(j+1));
								j--;
							}
							loopSubkeys(++j);
						}, con);
					}

					function loopIdentities(j) {
						if(j == it.identities.length) { loopAttributes(0); return; }
						
						keys.removeEmptyIdentity(it.id, it.identities[j].id, function(err, removed) {
							if(err) { rollback(err); return; }
							
							if(removed)
							{
								uploaded.failed.push(utils.extend(it.identities[j], { err: new i18n.Error_("Identity without signatures.") }));
								it.identities = it.identities.slice(0, j).concat(it.identities.slice(j+1));
								loopIdentities(j); // Not j++ as we have just removed one
							}
							else
							{
								if(userId)
								{
									users.addIdentityToKeyring(userId, it.id, it.identities[j].id, function(err) {
										if(err)
											console.warn("Error adding identity to user keyring", err);
										
										checkGroup();
									}, con);
								}
								else
									checkGroup();
								
								function checkGroup() {
									if(groupId)
									{
										groups.addIdentityToKeyring(groupId, it.id, it.identities[j].id, function(err) {
											if(err)
												console.warn("Error adding identity to group keyring", err);
											
											loopIdentities(++j);
										}, con);
									}
									else
										loopIdentities(++j);
								}
							}
						}, con);
					}
					
					function loopAttributes(j) {
						if(j == it.attributes.length) { after(); return; }
						
						keys.removeEmptyAttribute(it.id, it.attributes[j].id, function(err, removed) {
							if(err) { rollback(err); return; }
							
							if(removed)
							{
								uploaded.failed.push(utils.extend(it.attributes[j], { err: new i18n.Error_("Attribute without signatures.") }));
								it.attributes = it.attributes.slice(0, j).concat(it.attributes.slice(j+1));
								loopAttributes(j); // Not j++ as we have just removed one
							}
							else
							{
								if(userId)
								{
									users.addAttributeToKeyring(userId, it.id, it.attributes[j].id, function(err) {
										if(err)
											console.warn("Error adding attribute to user keyring", err);
										
										checkGroup();
									}, con);
								}
								else
									checkGroup();
								
								function checkGroup() {
									if(groupId)
									{
										groups.addAttributeToKeyring(groupId, it.id, it.attributes[j].id, function(err) {
											if(err)
												console.warn("Error adding attribute to group keyring", err);
											
											loopAttributes(++j);
										}, con);
									}
									else
										loopAttributes(++j);
								}
							}
						}, con);
					}
					
					function after() {
						keys.removeEmptyKey(it.id, function(err, removed) {
							if(err) { rollback(err); return; }
							
							if(removed)
							{
								uploaded.failed.push(utils.extend(it, { err: new i18n.Error_("Key without signatures, subkeys, identities or attributes.") }));
								uploaded.uploadedKeys = uploaded.uploadedKeys.slice(0, i).concat(uploaded.uploadedKeys.slice(i+1));
								i--;
							}
							loopKeys(++i);
						}, con);
					}
				}
			}
		});
	});
}

function _uploadKey(con, info, callback) {
	keys.keyExists(info.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			var transaction = utils.generateRandomString(43);
			con.query('SAVEPOINT "'+transaction+'"', [ ], function(err) {
				if(err) { callback(err); return; }
				
				con.query('INSERT INTO "keys" ( "id", "date", "binary" ) VALUES ( $1, $2, $3 )', [ info.id, info.date, info.binary ], function(err) {
					if(err) { callback(err); return; }
					
					keysTrust.handleKeyUpload(info.id, function(err) {
						if(err) {
							con.query('ROLLBACK TO "'+transaction+'"', [ ], function(err2) {
								if(err2) { console.warn("Error rolling back key transaction", err2); }
								callback(err);
							});
						}
						else
							callback(null);
					}, con);
				});
			});
		}
	}, con);
}

function _uploadIdentity(con, info, keyInfo, callback) {
	keys.identityExists(info.id, keyInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
			con.query('INSERT INTO "keys_identities" ( "id", "key", "name", "email" ) VALUES ( $1, $2, $3, $4 )', [ info.id, keyInfo.id, info.name, info.email ], callback);
	}, con);
}

function _uploadAttribute(con, info, keyInfo, callback) {
	keys.attributeExists(info.id, keyInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
			con.query('INSERT INTO "keys_attributes" ( "id", "key", "binary" ) VALUES ( $1, $2, $3 )', [ info.id, keyInfo.id, info.binary ], callback);
	}, con);
}

function _uploadKeySignature(con, info, objInfo, keyInfo, callback) { // keyInfo == objInfo in this case
	keys.keySignatureExists(info.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			var transaction = utils.generateRandomString(43);
			con.query('SAVEPOINT "'+transaction+'"', [ ], function(err) {
				if(err) { callback(err); return; }
				
				con.query('INSERT INTO "keys_signatures" ( "id", "key", "issuer", "date", "binary", "sigtype", "expires" ) VALUES ( $1, $2, $3, $4, $5, $6, $7 )', [ info.id, objInfo.id, info.issuer, info.date, info.binary, info.sigtype, info.expires ], function(err) {
					if(err) { callback(err); return; }
					
					keysTrust.verifyKeySignature(info.id, function(err, verified) {
						if(err) {
							con.query('ROLLBACK TO "'+transaction+'"', [ ], function(err2) {
								if(err2) { console.warn("Error rolling back key signature transaction", err2); }
								callback(err);
							});
						}
						else if(verified === false)
							callback(new i18n.Error_("Bad signature."));
						else
							callback(null);
					}, con);
				});
			});
		}
	}, con);
}

function _uploadIdentitySignature(con, info, objInfo, keyInfo, callback) {
	keys.identitySignatureExists(info.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			var transaction = utils.generateRandomString(43);
			con.query('SAVEPOINT "'+transaction+'"', [ ], function(err) {
				if(err) { callback(err); return; }
				
				con.query('INSERT INTO "keys_identities_signatures" ( "id", "identity", "key", "issuer", "date", "binary", "sigtype", "expires" ) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )', [ info.id, objInfo.id, keyInfo.id, info.issuer, info.date, info.binary, info.sigtype, info.expires ], function(err) {
					keysTrust.verifyIdentitySignature(info.id, function(err, verified) {
						if(err) {
							con.query('ROLLBACK TO "'+transaction+'"', [ ], function(err2) {
								if(err2) { console.warn("Error rolling back identity signature transaction", err2); }
								callback(err);
							});
						}
						else if(verified === false)
							callback(new i18n.Error_("Bad signature."));
						else
							callback(null);
					}, con);
				});
			});
		}
	}, con);
}

function _uploadAttributeSignature(con, info, objInfo, keyInfo, callback) {
	keys.attributeSignatureExists(info.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			var transaction = utils.generateRandomString(43);
			con.query('SAVEPOINT "'+transaction+'"', [ ], function(err) {
				if(err) { callback(err); return; }
				
				con.query('INSERT INTO "keys_attributes_signatures" ( "id", "attribute", "key", "issuer", "date", "binary", "sigtype", "expires" ) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )', [ info.id, objInfo.id, keyInfo.id, info.issuer, info.date, info.binary, info.sigtype, info.expires ], function(err) {
					keysTrust.verifyAttributeSignature(info.id, function(err, verified) {
						if(err) {
							con.query('ROLLBACK TO "'+transaction+'"', [ ], function(err2) {
								if(err2) { console.warn("Error rolling back attribute signature transaction", err2); }
								callback(err);
							});
						}
						else if(verified === false)
							callback(new i18n.Error_("Bad signature."));
						else
							callback(null);
					}, con);
				});
			});
		}
	}, con);
}

exports.uploadKey = uploadKey;