var db = require("./database");
var pgp = require("node-pgp");
var keys = require("./keys");
var keyrings = require("./keyrings");
var i18n = require("./i18n");

/**
 * Search for keys in the database.
 * @param string {String} The string to search for. Can be a key ID or fingerprint or a string that is contained in an identity of a key.
 * @param keyring {keyrings.Keyring} A keyring to filter the search results for, else only show keys that are public.
*/
function search(string, keyring, con) {
	var ret = new pgp.Fifo();

	if(string.length < 3)
	{
		ret._end(new i18n.Error_("The search string is too short."));
		return;
	}
	
	var searchInIdentities = true;
	
	if([ 10, 18, 34, 42 ].indexOf(string.length) != -1 && string.match(/^0x/i))
	{
		string = string.substring(2);
		searchInIdentities = false;
	}
	
	if(string.length == 8)
		_searchForKeyByShortId(string, keyring, ret, idsearch, con);
	else if(string.length == 16)
		_searchForKeyByLongId(string, keyring, ret, idsearch, con);
	else if(string.length == 32 || string.length == 40)
		_searchForKeyByFingerprint(string, keyring, ret, idsearch, con);
	else
		idsearch(null);
	
	function idsearch(err) {
		if(err) { ret._end(err); return; }
		
		if(searchInIdentities)
		{
			_searchInIdentities(string, keyring, ret, function(err) {
				ret._end(err);
			}, con);
		}
		else
			ret._end();
	}
	
	return ret;
}

function _searchInIdentities(string, keyring, ret, callback, con) {
	var query = '\
	SELECT DISTINCT ON ("id", "identity") "keys"."id" AS "id", "keys"."expires" AS "expires", "keys"."revokedby" AS "revokedby", "found"."id" AS "identity", "found"."perm" AS "perm" FROM (\
		      SELECT "id", "key", "perm_namesearch" AS "perm" FROM "keys_identities" WHERE LOWER("name") = LOWER($1)\
		UNION SELECT "id", "key", "perm_emailsearch" AS "perm" FROM "keys_identities" WHERE LOWER("email") = LOWER($1)\
		UNION SELECT "id", "key", ( "perm_namesearch" AND "perm_emailsearch" ) AS "perm" FROM "keys_identities" WHERE LOWER("id") LIKE \'%\' || LOWER($1) || \'%\'\
	) AS "found", "keys" WHERE "found"."key" = "keys"."id";';
	db.fifoQuery(query, [ string ], function(err, identityRecords) {
		if(err) { callback(err); return; }
		
		next();
		function next() {
			identityRecords.next(function(err, identityRecord) {
				if(err === true) { callback(null); return; }
				else if(err) { callback(err); return; }
				
				if(identityRecord.perm)
				{
					ret._add(identityRecord);
					next();
				}
				else if(keyring)
				{
					keyrings.keyringContainsIdentity(keyring, identityRecord.id, identityRecord.identity, function(err, contains) {
						if(err) { callback(err); return; }
						
						if(contains)
							ret._add(identityRecord);
						next();
					}, con);
				}
				else
					next();
			});
		}
	}, con);
}

function _searchForKeyByShortId(shortId, keyring, ret, callback, con) {
	_searchForKey('SELECT "id","expires","revokedby","perm_idsearch" FROM "keys" WHERE SUBSTRING("id" FROM 9 FOR 8) = $1', [ shortId.toUpperCase() ], keyring, ret, callback, con);
}

function _searchForKeyByLongId(longId, keyring, ret, callback, con) {
	_searchForKey('SELECT "id","expires","revokedby","perm_idsearch" FROM "keys" WHERE "id" = $1', [ shortId.toUpperCase() ], keyring, ret, callback, con);
}

function _searchForKeyByFingerprint(fingerprint, keyring, ret, callback, con) {
	_searchForKey('SELECT "id","expires","revokedby","perm_idsearch" FROM "keys" WHERE "fingerprint" = $1', [ fingerprint.toUpperCase() ], keyring, ret, callback, con);
}

function _searchForKey(query, args, keyring, ret, callback, con) {
	db.fifoQuerySync(query, args, con).forEachSeries(function(keyRecord, cb) {
		_addKey(keyRecord, keyring, ret, function(err) {
			if(err) { cb(err); return; }
		
			checkSubkeys(keyRecord, cb);
		}, con, true);
	}, callback);
	
	// Check if the found key is a sub-key of another key (or even several ones), if so, list that
	function checkSubkeys(keyRecord, cb) {
		db.getEntries("keys_subkeys", [ "parentkey" ], { id: keyRecord.id }, function(err, subkeyRecords) {
			if(err) { cb(err); return; }
			
			next();
			function next() {
				subkeyRecords.next(function(err, subkeyRecord) {
					if(err === true) { cb(null); return; }
					else if(err) { cb(err); return; }
					
					db.getEntry("keys", [ "id", "expires", "revokedby", "perm_idsearch" ], { id: subkeyRecord.parentkey }, function(err, parentkeyRecord) {
						if(err) { cb(err); return; }
						
						parentkeyRecord.subkey = keyRecord;
						_addKey(parentkeyRecord, keyring, ret, cb, con, false);
					}, con);
				});
			}
		}, con);
	}
}

function _addKey(keyRecord, keyring, ret, callback, con, checkShouldList) {
	if(checkShouldList)
	{
		_shouldListKey(keyRecord.id, function(err, shouldList) {
			if(err)
				callback(err);
			else if(shouldList)
				_addKey(keyRecord, keyring, ret, callback, con, false);
			else
				callback(null);
		});
		return;
	}
	
	if(keyRecord.perm_idsearch)
		doAdd();
	else if(keyring)
	{
		keyrings.keyringContainsKey(keyring, keyRecord.id, function(err, contains) {
			if(err) { callback(err); return; }
			
			if(contains)
				doAdd();
			else
				callback(null);
		}, con);
	}
	else
		callback(null);

	function doAdd()
	{
		keys.getPrimaryIdentity(keyRecord.id, keyring, function(err, identityRecord) {
			if(err) { callback(err); return; }
			
			if(identityRecord != null)
				keyRecord.identity = identityRecord.id;
			ret._add(keyRecord);
			callback(null);
		}, con);
	}
}

// If this is just a subkey, do not list it
function _shouldListKey(keyId, callback, con) {
	db.entryExists("keys_identities", { key: keyId }, function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null, true);
		else
		{
			db.entryExists("keys_attributes", { key: keyId }, function(err, exists) {
				if(err)
					callback(err);
				else if(exists)
					callback(null, true);
				else
				{
					db.entryExists("keys_subkeys", { parentkey: keyId }, function(err, exists) {
						if(err)
							callback(err);
						else if(exists)
							callback(null, true);
						else
						{
							db.query1('SELECT COUNT(*) FROM "keys_signatures" WHERE "key" = $1 AND "sigtype" NOT IN ( $2, $3 ) LIMIT 1', [ keyId, pgp.consts.SIG.SUBKEY, pgp.consts.SIG.SUBKEY_REVOK ], function(err, no) {
								if(err)
									callback(err);
								else
									callback(null, no > 0);
							}, con);
						}
					}, con);
				}
			}, con);
		}
	}, con);
}

exports.search = search;