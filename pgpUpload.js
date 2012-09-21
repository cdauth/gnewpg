var pgp = require("node-pgp");
var db = require("./database");
var pgpBasic = require("./pgpBasic");
var pgpTrust = require("./pgpTrust");
var i18n = require("./i18n");

/**
 * Stores keys into the database.
 * @param key {Buffer} The key(s) in binary format.
 * @param callback {Function} Is run when the uploading has finished. Arguments: err
*/
function uploadKey(key, callback, con) {
	db.getConnection_(con, function(err, con) {
		if(err) { callback(err); return; }

		var split = pgp.packets.splitPackets(key);
		var uploaded = {
			uploaded : [ ],
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
	
		function readNextPacket() {
			split.next(function(err, type, header, body) {
				if(err)
				{
					if(err === true)
						end();
					else
						callback(err, uploaded);
					return;
				}
				
				pgp.packetContent.getPacketInfo(type, body, function(err, info) {
					if(err) { callback(err, uploaded); return; }

					var func = null;
					pktswitch: switch(info.pkt) {
						case pgp.consts.PKT.PUBLIC_KEY:
							_uploadKey(con, info, function(err) {
								if(err) { uploaded.failed.push({ type: type, id: info.id, err: err }); return; }
								
								lastKey = info;
								lastKeyUpl = { id: info.id, signatures: [ ], subkeys: [ ], identities: [ ], attributes: [ ] }
								lastSubkey = lastId = lastAttr = null;

								uploaded.uploadedKeys.push(lastKeyUpl);
								readNextPacket();
							});
							break;
						case pgp.consts.PKT.PUBLIC_SUBKEY:
							_uploadKey(con, info, function(err) {
								if(err) { uploaded.failed.push({ type: type, id: info.id, err: err }); return; }
								
								lastSubkey = info;
								lastSubkeyUpl = { id: info.id, signatures: [ ], subkeys: [ ], identities: [ ], attributes: [ ] };
								lastId = lastAttr = null;

								if(lastKey)
									lastKeyUpl.subkeys.push(lastSubkeyUpl);
								else
									uploaded.uploadedKeys.push(lastSubkeyUpl);
								readNextPacket();
							});
							break;
						case pgp.consts.PKT.USER_ID:
							if(lastKey == null) { uploaded.failed.push({ type: type, id: info.id, err: new i18n.Error("No associated key.") }); break; }
							
							_uploadIdentity(con, info, lastKey, function(err) {
								if(err) { uploaded.failed.push({ type: type, id: info.id, err: err }); return; }
								
								lastId = info;
								lastIdUpl = { id: info.id, signatures: [ ] };
								lastSubkey = lastAttr = null;
								
								lastKeyUpl.identities.push(lastIdUpl);
								readNextPacket();
							});
							break;
						case pgp.consts.PKT.ATTRIBUTE:
							if(lastKey == null) { uploaded.failed.push({ type: type, id: info.id, err: new i18n.Error("No associated key.") }); break; }
							
							_uploadAttribute(con, info, lastKey, function(err) {
								if(err) { uploaded.failed.push({ type: type, id: info.id, err: err }); return; }
								
								lastAttr = info;
								lastAttrUpl = { id: info.id, signatures: [ ] };
								lastSubkey = lastId = null;
								
								lastKeyUpl.attributes.push(lastAttrUpl);
								readNextPacket();
							});
							break;
						case pgp.consts.PKT.SIGNATURE:
							switch(info.sigtype)
							{
								case pgp.consts.SIG.CERT_0:
								case pgp.consts.SIG.CERT_1:
								case pgp.consts.SIG.CERT_2:
								case pgp.consts.SIG.CERT_3:
								case pgp.consts.SIG.CERT_REVOK:
									if(lastId == null && lastAttr == null)
									{
										uploaded.failed.push({ type: type, id: info.id, issuer: info.issuer, date: info.date, err: new i18n.Error("Signature type %x is only acceptable on identities and attributes.", info.sigtype) });
										break pktswitch;
									}
									break;
								case pgp.consts.SIG.SUBKEY:
								case pgp.consts.SIG.SUBKEY_REVOK:
									if(lastSubkey == null)
									{
										uploaded.failed.push({ type: type, id: info.id, issuer: info.issuer, date: info.date, err: new i18n.Error("Signature type %x is only acceptable on subkeys.", info.sigtype) });
										break pktswitch;
									}
									break;
								case pgp.consts.SIG.KEY:
								case pgp.consts.SIG.KEY_BY_SUBKEY:
								case pgp.consts.SIG.KEY_REVOK:
									lastSubkey = lastId = lastAttr = null;
									break;
								default:
									uploaded.failed.push({ type: type, id: info.id, issuer: info.issuer, date: info.date, err: new i18n.Error("Unsupported signature type %x.", info.sigtype) });
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
								info.subkey = lastSubkey.id;
							}
							else if(lastId != null)
							{
								func = _uploadIdentitySignature;
								obj = lastId;
								objUpl = lastIdUpl;
								info.identity = lastId.id;
							}
							else if(lastAttr != null)
							{
								func = _uploadAttributeSignature;
								obj = lastAttr;
								objUpl = lastAttrUpl;
								info.attribute = lastAttr.id;
							}
							else if(lastKey != null)
							{
								func = _uploadKeySignature;
								obj = lastKey;
								objUpl = lastKeyUpl;
							}
							else
							{
								uploaded.failed.push({ type : type, id: info.id, issuer: info.issuer, date: info.date, err: new i18n.Error("No associated object for signature.") });
								break;
							}
							
							func(con, info, obj, lastKey, _, function(err) {
								if(err) { uploaded.failed.push({ type: type, id: info.id, issuer: info.issuer, date: info.date, err: err }); return; }
								
								obj.signatures.push({ id: info.id, issuer: info.issuer, date: info.date });
								readNextPacket();
							});
							break;
						default:
							uploaded.failed.push({ type: type, err: new Error(_("Unknown packet.")) });
					}
				});
			});
		}
		
		function end() {
			// TODO: Check if there have been uploaded any keys, identities or attributes without any signatures
			// TODO: Check:
			/*if(ret.hashedSubPackets[consts.SIGSUBPKT.REV_KEY])
				{
					ret.hashedSubPackets[consts.SIGSUBPKT.REV_KEY].forEach(function(it) {
						if(it.value.sensitive)
							ret.exportable = false;
					});
				}*/

			callback(null, uploaded);
		}
	});
}

function _uploadKey(con, info, keyInfo, _, callback) {
	pgpBasic.keyExists(info.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			con.query('INSERT INTO "keys" ( "id", "binary" ) VALUES ( $1, $2 )', [ pgpBasic._encodeKeyId(info.id), info.binary ], function(err) {
				if(err) { callback(err); return; }
				
				// TODO: Verify signatures that have been made with this key
				callback(null);
			});
		}
	});
}

function _uploadIdentity(con, info, keyInfo, _, callback) {
	pgpBasic.identityExists(info.id, keyInfo.id function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
			con.query('INSERT INTO "keys_identities" ( "id", "key", "name", "email" ) VALUES ( $1, $2, $3, $4 )', [ info.id, pgpBasic._encodeId(keyInfo.id), info.name, info.email ], callback);
	});
}

function _uploadAttribute(con, info, keyInfo, _, callback) {
	pgpBasic.attributeExists(info.id, keyInfo.id function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
			con.query('INSERT INTO "keys_attributes" ( "id", "key", "binary" ) VALUES ( $1, $2, $3 )', [ info.id, pgpBasic._encodeId(keyInfo.id), info.binary ], callback);
	});
}

function _uploadKeySignature(con, info, objInfo, keyInfo, _, callback) { // keyInfo == objInfo in this case
	pgpBasic.keySignatureExists(info.id, objInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			pgpTrust.verifyKeySignature(keyInfo.binary, info.issuer, info.binary, function(verified) {
				if(verified === false)
					callback(new Error(_("Bad signature.")));
				else
					con.query('INSERT INTO "keys_signatures" ( "id", "key", "issuer", "date", "binary", "sigtype", "expires", "verified" ) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )', [ info.id, pgpBasic._encodeId(objInfo.id), info.issuer, info.date, info.binary, info.sigtype, info.expires, !!verified ], callback);
			}, con);
		}
	});
}

function _uploadIdentitySignature(con, info, objInfo, keyInfo, _, callback) {
	pgpBasic.identitySignatureExists(info.id, objInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			pgpTrust.verifyIdentitySignature(
			con.query('INSERT INTO "keys_identities_signatures" ( "id", "identity", "key", "issuer", "date", "binary", "sigtype", "expires" ) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )', [ info.id, pgpBasic._encodeId(objInfo.id), pgpBasic._encodeId(keyInfo.id), info.issuer, info.date, info.binary, info.sigtype, info.expires ], callback);
	});
}

function _uploadAttributeSignature(con, info, objInfo, keyInfo, _, callback) {
	pgpBasic.attributeSignatureExists(info.id, objInfo.id, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
			con.query('INSERT INTO "keys_identities_signatures" ( "id", "attribute", "key", "issuer", "date", "binary", "sigtype", "expires" ) VALUES ( $1, $2, $3, $4, $5, $6, $7, $8 )', [ info.id, pgpBasic._encodeId(objInfo.id), pgpBasic._encodeId(keyInfo.id), info.issuer, info.date, info.binary, info.sigtype, info.expires ], callback);
	});
}