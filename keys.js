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

/**
 * Exports the specified keys.
 * @param keys {Array} An array of key records.objects. Each object contains an entry `id`, which is the ID of the key to export, and entries `signatures`, `subkeys`,
 *                     `identities`, and `attributes`, each of which is an array of objects that contain the `id` (and `key` for `identities` and
 *                     `attributes`) and `signatures` entry.
 * @return {pgp.BufferedStream}
*/
function exportKeys(keys, con) {
	var ret = new pgp.BufferedStream();
	
	var formats = {
		"key" : { table: "keys", pkt: pgp.consts.PKT.PUBLIC_KEY, sub: [ "sigKey", "subkey", "id", "attr" ] },
		"sigKey" : { idx: "signatures", table: "keys_signatures", pkt: pgp.consts.PKT.SIGNATURE, sub: [ ] },
		"subkeys" : { idx: "subkeys", table: "keys", pkt: pgp.consts.PKT.PUBIC_SUBKEY, sub: [ "sigKey" ] },
		"id" : { idx: "identities", table: "keys_identities", pkt: pgp.consts.PKT.USER_ID, sub: [ "sigId" ] },
		"sigId" : { idx: "signatures", table: "keys_identities_signatures", pkt: pgp.consts.PKT.SIGNATURE, sub: [ ] },
		"attr" : { idx: "attributes", table: "keys_attributes", pkt: pgp.consts.PKT.ATTRIBUTE, sub: [ "sigAttr" ] },
		"sigAttr" : { idx: "signatures", table: "keys_attributes_signatures", pkt: pgp.consts.PKT.SIGNATURE, sub: [ ] }
	};
	
	handleObjects(keys, formats.key, function(err) {
		ret._endData(err);
	});
	
	return ret;

	
	function handleObjects(parentObj, format, cb) {
		async.forEachSeries(parentObj, function(obj, objCb) {
			fetchBinary(obj, format.table, function(err, binary) {
				if(err) { objCb(err); return; }
				
				ret._sendData(pgp.packets.generatePacket(format.pkt, binary));
				async.forEachSeries(format.sub, function(sub, subCb) {
					handleObjects(obj[formats[sub].idx] || [ ], formats[sub], subCb);
				}, objCb);
			});
		}, cb);
	}
	
	function fetchBinary(obj, table, cb) {
		if(table == "keys_identities")
			cb(null, new Buffer(obj.id, "utf8"));
		else if(obj.binary)
			cb(null, obj.binary);
		else
		{
			var filter = { id: obj.id };
			if(table == "keys_attributes")
				filter.key = obj.key;
			db.getEntry(table, [ "binary" ], filter, function(err, ret) {
				if(err)
					cb(err);
				else if(ret == null)
					cb(new i18n.Error_("Could not find object %s.", obj.id));
				else
					cb(null, ret.binary);
			}, con);
		}
	}
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
exports.exportKeys = exportKeys;