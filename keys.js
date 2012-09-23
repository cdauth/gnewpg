var pgp = require("node-pgp");
var db = require("./database");

function keyExists(id, callback, con) {
	db.xExists("keys", { "id" : id }, callback, con);
}

function getKey(id, callback, con) {
	getKeys({ "id" : id }, callback, true, con);
}

function getKeys(filter, callback, justOne, con) {
	db.getWithFilter('SELECT "id", "binary", "perm_idsearch", "perm_searchengines", "expires", "revokedby", "primary_identity", "user" FROM "keys"',
		filter, callback, justOne, con);
}

function getSubkeys(filter, callback, justOne, con) {
	db.getWithFilter('SELECT "id", "binary", "parentkey", "expires", "revokedby" FROM "keys_subkeys"',
		filter, callback, justOne, con);
}

function identityExists(id, parentId, callback, con) {
	db.xExists("keys_identities", { "id" : id, "key" : parentId }, callback, con);
}

function getIdentity(id, parentId, callback, con) {
	getIdentities({ "id" : id, "key" : parentId }, callback, true, con);
}

function getIdentities(filter, callback, justOne, con)
{
	db.getWithFilter('SELECT "id", "key", "name", "email", "perm_public", "perm_namesearch", "perm_emailsearch", "email_blacklisted" FROM "keys_identities"',
		filter, callback, justOne, con);
}


function attributeExists(id, parentId, callback, con) {
	db.xExists("keys_attributes", { "id" : id, "key" : parentId }, callback, con);
}

function getAttribute(id, parentId, callback, con) {
	getAttributes({ "id" : id, "key" : parentId }, callback, true, con);
}

function getAttributes(filter, callback, justOne, con) {
	db.getWithFilter('SELECT "id", "key", "binary", "perm_public" FROM "keys_attributes"',
		filter, callback, justOne, con);
}


function keySignatureExists(id, callback, con) {
	db.xExists("keys_signatures", { "id" : id }, callback, con);
}

function identitySignatureExists(id, callback, con) {
	db.xExists("keys_identities_signatures", { "id" : id }, callback, con);
}

function attributeSignatureExists(id, callback, con) {
	db.xExists("keys_attributes_signatures", { "id" : id }, callback, con);
}

function getSignature(id, callback, con) {
	getAllSignatures({ id: id }, callback, true, con);
}

function getAllSignatures(filter, callback, justOne, con) {
	db.getWithFilter('SELECT "id", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revokedby", "table", "objectcol" FROM "keys_signatures_all"',
		filter, callback, justOne, con);
}

function getKeySignature(id, callback, con) {
	getKeySignatures({ id: id }, callback, true, con);
}
	
function getKeySignatures(filter, callback, justOne, con) {
	db.getWithFilter('SELECT "id", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revokedby" FROM "keys_signatures"',
		filter, callback, justOne, con);
}

function getIdentitySignature(id, callback, con) {
	getIdentitySignatures({ id: id }, callback, true, con);
}

function getIdentitySignatures(filter, callback, justOne, con) {
	db.getWithFilter('SELECT "id", "identity", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revokedby" FROM "keys_identities_signatures"',
		filter, callback, justOne, con);
}

function getAttributeSignature(id, callback, con) {
	getAttributeSignatures({ id: id }, callback, true, con);
}

function getAttributeSignatures(filter, callback, justOne, con) {
	db.getWithFilter('SELECT "id", "attribute", "key", "issuer", "date", "binary", "verified", "sigtype", "expires", "revokedby" FROM "keys_attributes_signatures"',
		filter, callback, justOne, con);
}

function removeEmptyKey(keyId, callback, con) {
	getKeySignatures({ key: keyId }, function(err, one) {
		if(err) callback(err);
		else if(one) callback(null, false);
		else
		{
			getIdentities({ key: keyId }, function(err, one) {
				if(err) callback(err);
				else if(one) callback(null, false);
				else
				{
					getAttributes({ key: keyId }, function(err, one) {
						if(err) callback(err);
						else if(one) callback(null, false);
						else
						{
							db.query('DELETE FROM "keys" WHERE "id" = $1', [ keyId ], function(err) {
								if(err)
									callback(err);
								else
									callback(null, true);
							}, con);
						}
					}, true, con);
				}
			}, true, con);
		}
	}, true, con);
}

function removeEmptyIdentity(keyId, id, callback, con) {
	getIdentitySignatures({ key: keyId, identity: id }, function(err, one) {
		if(err)
			callback(err);
		else if(one)
			callback(null, false);
		else
		{
			db.query('DELETE FROM "keys_identities" WHERE "key" = $1 AND "id" = $2', [ keyId, id ], function(err) {
				if(err)
					callback(err);
				else
					callback(null, true);
			}, con);
		}
	}, true, con);
}

function removeEmptyAttribute(keyId, attrId, callback, con) {
	getAttributeSignatures({ key: keyId, attribute: attrId }, function(err, one) {
		if(err)
			callback(err);
		else if(one)
			callback(null, false);
		else
		{
			db.query('DELETE FROM "keys_attributes" WHERE "key" = $1 AND "id" = $2', [ keyId, attrId ], function(err) {
				if(err)
					callback(err);
				else
					callback(null, true);
			}, con);
		}
	}, true, con);
}

exports.keyExists = keyExists;
exports.identityExists = identityExists;
exports.attributeExists = attributeExists;
exports.keySignatureExists = keySignatureExists;
exports.identitySignatureExists = identitySignatureExists;
exports.attributeSignatureExists = attributeSignatureExists;

exports.getKey = getKey;
exports.getSubkeys = getSubkeys;
exports.getIdentity = getIdentity;
exports.getAttribute = getAttribute;
exports.getSignature = getSignature;
exports.getKeySignature = getKeySignature;
exports.getIdentitySignature = getIdentitySignature;
exports.getAttributeSignature = getAttributeSignature;

exports.getKeys = getKeys;
exports.getIdentities = getIdentities;
exports.getAttributes = getAttributes;
exports.getKeySignatures = getKeySignatures;
exports.getAllSignatures = getAllSignatures;
exports.getIdentitySignatures = getIdentitySignatures;
exports.getAttributeSignatures = getAttributeSignatures;

exports.removeEmptyKey = removeEmptyKey;
exports.removeEmptyIdentity = removeEmptyIdentity;
exports.removeEmptyAttribute = removeEmptyAttribute;