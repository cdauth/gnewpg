var pgp = require("node-pgp");
var db = require("./database");
var keyrings = require("./keyrings");

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
	}, true, con);
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

exports.removeEmptyKey = removeEmptyKey;
exports.removeEmptyIdentity = removeEmptyIdentity;
exports.removeEmptyAttribute = removeEmptyAttribute;
exports.getPrimaryIdentity = getPrimaryIdentity;