var pgp = require("node-pgp");
var db = require("./database");
var pgpBasic = require("./pgpBasic");
var pgpTrust = require("./pgpTrust");
var i18n = require("./i18n");
var utils = require("./utils");

/**
 * Stores keys into the database.
 * @param key {Buffer|Readable Stream|String|pgp.BufferedStream} The key(s) in binary format.
 * @param callback {Function} Is run when the uploading has finished. Arguments: err
*/
function uploadKey(key, callback) {
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
									if(err) { uploaded.failed.push(utils.extend(upl, { err: err })); readNextPacket(); return; }
									
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
									if(err) { uploaded.failed.push(utils.extend(upl, { err: err })); readNextPacket(); return; }
									
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
									if(err) { uploaded.failed.push(utils.extend(upl, { err: err })); readNextPacket(); return; }
									
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
									if(err) { uploaded.failed.push(utils.extend(upl, { err: err })); readNextPacket(); return; }
									
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
									func = _uploadSubkeySignature;
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
									if(err) { uploaded.failed.push(utils.extend(upl, { err: err })); return; }
									
									obj.signatures.push(upl);
									readNextPacket();
								});
								break;
							default:
								uploaded.failed.push({ type: type, err: new i18n.Error_("Unknown packet.") });
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

					function loopSubkeys(j) {
						if(j == it.subkeys.length) { loopIdentities(0); return; }
						
						pgpBasic.removeEmptyKey(it.subkeys[j].id, function(err, removed) {
							if(err) { rollback(err); return; }

							if(removed)
							{
								uploaded.failed.push(utils.extend(it.subkeys[j], { err: new i18n.Error_("Subkey without signatures.") }));
								it.subkeys = it.subkeys.slice(0, j).concat(it.subkeys.slice(j+1));
							}
							loopSubkeys(++j);
						}, con);
					}

					function loopIdentities(j) {
						if(j == it.identities.length) { loopAttributes(0); return; }
						
						pgpBasic.removeEmptyIdentity(it.identities[j], function(err, removed) {
							if(err) { rollback(err); return; }
							
							if(removed)
							{
								uploaded.failed.push(utils.extend(it.identities[j], { err: new i18n.Error_("Identity without signatures.") }));
								it.identities = it.identities.slice(0, j).concat(it.identities.slice(j+1));
							}
							loopIdentities(++j);
						}, con);
					}
					
					function loopAttributes(j) {
						if(j == it.attributes.length) { after(); return; }
						
						pgpBasic.removeEmptyAttributes(it.attributes[j], function(err, removed) {
							if(err) { rollback(err); return; }
							
							if(removed)
							{
								uploaded.failed.push(utils.extend(it.attributes[j], { err: new i18n.Error_("Attribute without signatures.") }));
								it.attributes = it.attributes.slice(0, j).concat(it.attributes.slice(j+1));
							}
							loopAttributes(++j);
						}, con);
					}
					
					function after() {
						pgpBasic.removeEmptyKey(it.id, function(err, removed) {
							if(err) { rollback(err); return; }
							
							if(removed)
							{
								uploaded.failed.push(utils.extend(it, { err: new i18n.Error_("Key without signatures, subkeys, identities or attributes.") }));
								uploaded.uploadedKeys = uploaded.uploadedKeys.slice(0, i).concat(uploaded.uploadedKeys.slice(i+1));
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
	pgpBasic.keyExists(info.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			con.query('INSERT INTO "keys" ( "id", "binary" ) VALUES ( $1, $2 )', [ pgpBasic._encodeKeyId(info.id), info.binary ], function(err) {
				if(err) { callback(err); return; }
				
				pgpTrust.handleKeyUpload(info.id, function(err) {
					if(err) { callback(err); return; }
					
					callback(null);
				}, con);
			}, con);
		}
	}, con);
}

function _uploadIdentity(con, info, keyInfo, callback) {
	pgpBasic.identityExists(info.id, keyInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
			con.query('INSERT INTO "keys_identities" ( "id", "key", "name", "email" ) VALUES ( $1, $2, $3, $4 )', [ info.id, pgpBasic._encodeId(keyInfo.id), info.name, info.email ], callback, con);
	}, con);
}

function _uploadAttribute(con, info, keyInfo, callback) {
	pgpBasic.attributeExists(info.id, keyInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
			con.query('INSERT INTO "keys_attributes" ( "id", "key", "binary" ) VALUES ( $1, $2, $3 )', [ info.id, pgpBasic._encodeId(keyInfo.id), info.binary ], callback, con);
	}, con);
}

function _uploadKeySignature(con, info, objInfo, keyInfo, callback) { // keyInfo == objInfo in this case
	pgpBasic.keySignatureExists(info.id, objInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			con.query('INSERT INTO "keys_signatures" ( "id", "key", "issuer", "date", "binary", "sigtype", "expires" ) VALUES ( $1, $2, $3, $4, $5, $6, $7 )', [ info.id, pgpBasic._encodeId(objInfo.id), info.issuer, info.date, info.binary, info.sigtype, info.expires ], function(err) {
				if(err) { callback(err); return; }
				
				pgpTrust.verifyKeySignature(info.id, function(err, verified) {
					if(err)
						callback(err);
					else if(verified === false)
						callback(new i18n.Error_("Bad signature."));
					else
						callback(null);
				}, con);
			}, con);
		}
	}, con);
}

function _uploadIdentitySignature(con, info, objInfo, keyInfo, callback) {
	pgpBasic.identitySignatureExists(info.id, objInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			con.query('INSERT INTO "keys_identities_signatures" ( "id", "identity", "key", "issuer", "date", "binary", "sigtype", "expires" ) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )', [ info.id, pgpBasic._encodeId(objInfo.id), pgpBasic._encodeId(keyInfo.id), info.issuer, info.date, info.binary, info.sigtype, info.expires ], function(err) {
				pgpTrust.verifyIdentitySignature(info.id, function(err, verified) {
					if(err)
						callback(err);
					else if(verified === false)
						callback(new i18n.Error_("Bad signature."));
					else
						callback(null);
				}, con);
			}, con);
		}
	}, con);
}

function _uploadAttributeSignature(con, info, objInfo, keyInfo, callback) {
	pgpBasic.attributeSignatureExists(info.id, objInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			con.query('INSERT INTO "keys_identities_signatures" ( "id", "attribute", "key", "issuer", "date", "binary", "sigtype", "expires" ) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )', [ info.id, pgpBasic._encodeId(objInfo.id), pgpBasic._encodeId(keyInfo.id), info.issuer, info.date, info.binary, info.sigtype, info.expires ], function(err) {
				pgpTrust.verifyAttributeSignature(info.id, function(err, verified) {
					if(err)
						callback(err);
					else if(verified === false)
						callback(new i18n.Error_("Bad signature."));
					else
						callback(null);
				}, con);
			}, con);
		}
	}, con);
}

exports.uploadKey = uploadKey;