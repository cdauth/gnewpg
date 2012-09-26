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
				
				db.getEntriesSync("keys_signatures", [ "id", "binary" ], { key: keyId }, con).forEach(function(signatureRecord, cb2) {
					if(!selection || !selection.signatures || selection.signatures[signatureRecord.id] != false)
						ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.SIGNATURE, signatureRecord.binary));
					cb2();
				}, cb);
			},
			function(cb) {
				db.getEntriesSync("keys_identities", [ "id", "perm_public" ], { key: keyId }, con).forEach(function(identityRecord, cb2) {
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
							
							db.getEntriesSync("keys_identities_signatures", [ "binary" ], { key: keyId, identity: identityRecord.id }, con).forEach(function(signatureRecord, cb2) {
								if(!selection || !selection.signatures || selection.signatures[signatureRecord.id] != false)
									ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.SIGNATURE, signatureRecord.binary));
								cb2();
							}, cb2);
						}
					}
				}, cb);
			},
			function(cb) {
				db.getEntriesSync("keys_attributes", [ "id", "binary", "perm_public" ], { key: keyId }, con).forEach(function(attributeRecord, cb2) {
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
							
							db.getEntriesSync("keys_attributes_signatures", [ "binary" ], { key: keyId, attribute: attributeRecord.id }, con).forEach(function(attributeRecord, cb2) {
								if(!selection || !selection.signatures || selection.signatures[signatureRecord.id] != false)
									ret._sendData(pgp.packets.generatePacket(pgp.consts.PKT.SIGNATURE, attributeRecord.binary));
								cb2();
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

/*function getKeyWithSubobjects(keyId, keyring, callback, con) {
	db.getEntry("keys", "*", [ id: keyId ], function(err, keyRecord) {
		if(err) { callback(err, ret); return; }
		if(keyRecord == null) { callback(new i18n.Error_("Key %s not found.", keyId)); return; }
		
		keyRecord.signatures = [ ];
		keyRecord.subkeys = [ ];
		keyRecord.identities = [ ];
		keyRecord.attributes = [ ];
		
		async.series([
			function(cb) {
				if(keyRecord.perm_public)
					cb();
				else if(keyring)
				{
					keyrings.keyringContainsKey(keyId, function(err, contains) {
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
			function(cb) {
				db.getEntriesAtOnce("keys_signatures", "*", [ key: keyId ], function(err, signatureEntries) {
					if(err) { cb(err); return; }
					
					signatureEntries.forEach(function(it) {
						
					
					
		function addSignatures(obj, signatureEntries, cb) {
			next();
			function next() {
				signatureEntries.next(function(err, signatureEntry) {
					if(err === true) { cb(null); return; }
					else if(err) { cb(err); return; }
					
					obj.push(signatureEntry
}*/

exports.removeEmptyKey = removeEmptyKey;
exports.removeEmptyIdentity = removeEmptyIdentity;
exports.removeEmptyAttribute = removeEmptyAttribute;
exports.getPrimaryIdentity = getPrimaryIdentity;
exports.exportKey = exportKey;