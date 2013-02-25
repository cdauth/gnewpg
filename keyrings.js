var db = require("./database");
var util = require("util");
var keyringPg = require("node-pgp-postgres");
var pgp = require("node-pgp");

var p = pgp.utils.proxy;

function UnfilteredKeyring(con) {
	UnfilteredKeyring.super_.call(this, con);
}

util.inherits(UnfilteredKeyring, keyringPg._KeyringPostgres);

///////////////////////////////////////////////////////////////////////////////

function FilteredKeyring(con) {
	FilteredKeyring.super_.call(this, con);
}

util.inherits(FilteredKeyring, UnfilteredKeyring);

pgp.utils.extend(FilteredKeyring.prototype, {
	_maySeeKey : function(keyId, callback) {
		callback(null, false);
	},

	_maySeeIdentity : function(keyId, identityId, callback) {
		callback(null, false, false, false); // See, find by name, find by email
	},

	_maySeeAttribute : function(keyId, attributeId, callback) {
		callback(null, false);
	},

	_onAddKey : function(keyInfo, callback) {
		callback(null);
	},

	_onAddIdentity : function(keyId, identityInfo, callback) {
		callback(null);
	},

	_onAddAttribute : function(keyId, attributeInfo, callback) {
		callback(null);
	},

	getKeyList : __filterList("getKeyList", "_maySeeKey", 0),
	getIdentityList : __filterList("getIdentityList", "_maySeeIdentity", 1),
	getAttributeList : __filterList("getAttributeList", "_maySeeAttribute", 1),

	getKeys : __filterGetMultiple("getKeys", "_maySeeKey", 0),
	getIdentities : __filterGetMultiple("getIdentities", "_maySeeIdentity", 1),
	getAttributes : __filterGetMultiple("getAttributes", "_maySeeAttribute", 1),

	keyExists : __filterExists("keyExists", "_maySeeKey", 1),
	identityExists : __filterExists("identityExists", "_maySeeIdentity", 2),
	attributeExists : __filterExists("attributeExists", "_maySeeAttribute", 2),

	getKey : __filterGetSingle("getKey", "_maySeeKey", 1),
	getIdentity : __filterGetSingle("getIdentity", "_maySeeIdentity", 2),
	getAttribute : __filterGetSingle("getAttribute", "_maySeeAttribute", 2),

	addKey : __filterAdd("addKey", "_onAddKey", 1),
	addIdentity : __filterAdd("addIdentity", "_onAddIdentity", 2),
	addAttribute : __filterAdd("addAttribute", "_onAddAttribute", 2),

	searchIdentities : function(searchString) {
		var ret = FilteredKeyring.super_.prototype.searchIdentities.apply(this, arguments);
		searchString = searchString.toLowerCase();

		return ret.grep(p(this, function(keyRecord, next) {
			this._maySeeKey(keyRecord.id, p(this, function(err, may) {
				if(err || !may)
					return next(err, false);

				this._maySeeIdentity(keyRecord.id, keyRecord.identity.id, p(this, function(err, public, nameSearch, emailSearch) {
					if(err)
						return next(err);

					if(nameSearch && keyRecord.identity.name.toLowerCase().indexOf(searchString) != -1)
						next(null, true);
					else if(emailSearch && keyRecord.identity.email.toLowerCase().indexOf(searchString) != -1)
						next(null, true);
					else
						next(null, nameSearch && emailSearch);
				}));
			}));
		}));
	},

	searchByShortKeyId : function(keyId) {
		var ret = FilteredKeyring.super_.prototype.searchByShortKeyId.apply(this, arguments);
		return ret.grep(p(this, function(keyInfo, cb) {
			this._maySeeKey(keyInfo.id, cb);
		}));
	},

	searchByLongKeyId : function(keyId) {
		var ret = FilteredKeyring.super_.prototype.searchByLongKeyId.apply(this, arguments);
		return ret.grep(p(this, function(keyInfo, cb) {
			this._maySeeKey(keyInfo.id, cb);
		}));
	},

	searchByFingerprint : function(keyId) {
		var ret = FilteredKeyring.super_.prototype.searchByFingerprint.apply(this, arguments);
		return ret.grep(p(this, function(keyInfo, cb) {
			this._maySeeKey(keyInfo.id, cb);
		}));
	}
});

function __filterList(listFuncName, mayFuncName, argNo) {
	return function() {
		var t = this;
		var args = pgp.utils.toProperArray(arguments);

		return FilteredKeyring.super_.prototype[listFuncName].apply(t, args).grep(function(it, cb) {
			t[mayFuncName].apply(t, args.slice(0, argNo).concat([ it, cb ]));
		});
	};
}

function __filterGetMultiple(getFuncName, mayFuncName, argNo) {
	return function() {
		var t = this;
		var args = pgp.utils.toProperArray(arguments);

		// Add id to fields parameter
		if(args[argNo+1] && args[argNo+1].indexOf("id") == -1)
			args[argNo+1].push("id");

		return FilteredKeyring.super_.prototype[getFuncName].apply(t, args).grep(function(it, cb) {
			t[mayFuncName].apply(t, args.slice(0, argNo).concat([ it.id, cb ]));
		});
	};
}

function __filterExists(existsFuncName, mayFuncName, argNo) {
	return function() {
		var t = this;
		var args = pgp.utils.toProperArray(arguments);
		var _isTryingToAdd = args[argNo+1]; // Hack: If the exists function is called from the add() function to prevent
		                                    // duplicate addition, we ignore our restrictions

		FilteredKeyring.super_.prototype[existsFuncName].apply(t, args.slice(0, argNo).concat([ function(err, exists) {
			if(err || !exists || _isTryingToAdd)
				return args[argNo](err, exists);

			t[mayFuncName].apply(t, args);
		}]), _isTryingToAdd);
	};
}

function __filterGetSingle(getFuncName, mayFuncName, argNo) {
	return function() {
		var t = this;
		var args = pgp.utils.toProperArray(arguments);

		FilteredKeyring.super_.prototype[getFuncName].apply(t, args.slice(0, argNo).concat([ function(err, item) {
			if(err || item == null)
				return args[argNo](err, item);

			t[mayFuncName].apply(t, args.slice(0, argNo).concat([ function(err, may) {
				if(err)
					args[argNo](err);
				else if(may)
					args[argNo](null, item);
				else
					args[argNo](null, null);
			}]));
		}, args[argNo+1]]));
	};
}

function __filterAdd(addFuncName, handlerFuncName, argNo) {
	return function() {
		var t = this;
		var args = pgp.utils.toProperArray(arguments);

		FilteredKeyring.super_.prototype[addFuncName].apply(this, args.slice(0, argNo).concat([ function(err) {
			if(err)
				return args[argNo](err);

			t[handlerFuncName].apply(t, args);
		}]));
	}
}

///////////////////////////////////////////////////////////////////////////////

function AnonymousKeyring(con) {
	AnonymousKeyring.super_.call(this, con);
}

util.inherits(AnonymousKeyring, FilteredKeyring);

pgp.utils.extend(AnonymousKeyring.prototype, {
	_containsKey : function(keyId, callback) {
		callback(null, false);
	},

	_containsIdentity : function(keyId, identityId, callback) {
		callback(null, false);
	},

	_containsAttribute : function(keyId, attributeId, callback) {
		callback(null, false);
	},

	_maySeeKey : function(keyId, callback) {
		this._containsKey(keyId, p(this, function(err, contains) {
			if(err || contains)
				return callback(err, contains);

			db.getEntry(this._con, "keys_settings", [ "perm_idsearch" ], { id: keyId }, function(err, res) {
				if(err)
					return callback(err);

				callback(null, res != null && res.perm_idsearch);
			});
		}));
	},

	_maySeeIdentity : function(keyId, identityId, callback) {
		this._containsIdentity(keyId, identityId, p(this, function(err, contains) {
			if(err || contains)
				return callback(err, contains, contains, contains);

			db.getEntry(this._con, "keys_identities_settings", [ "perm_public", "perm_namesearch", "perm_emailsearch" ], { key: keyId, id: identityId }, function(err, res) {
				if(err)
					callback(err);
				else if(res == null)
					callback(null, false, false, false);
				else
					callback(null, res.perm_public, res.perm_namesearch, res.perm_emailsearch);
			})
		}));
	},

	_maySeeAttribute : function(keyId, attributeId, callback) {
		this._containsAttribute(keyId, attributeId, p(this, function(err, contains) {
			if(err || contains)
				return callback(err, contains);

			db.getEntry(this._con, "keys_identities_settings", [ "perm_public" ], { key: keyId, id: identityId }, function(err, res) {
				if(err)
					return callback(err);

				callback(null, res != null && res.perm_public);
			});
		}));
	}
});

///////////////////////////////////////////////////////////////////////////////

function SearchEngineKeyring(con) {
	SearchEngineKeyring.super_.call(this, con);
}

util.inherits(SearchEngineKeyring, AnonymousKeyring);

pgp.utils.extend(SearchEngineKeyring.prototype, {
	_maySeeKey : function(keyId, callback) {
		db.getEntry(this._con, "keys_settings", [ "perm_idsearch", "perm_searchengines" ], { id: keyId }, function(err, res) {
			if(err)
				return callback(err);

			callback(null, res != null && res.perm_idsearch && res.perm_searchengines);
		})
	}
});

///////////////////////////////////////////////////////////////////////////////

function TemporaryUploadKeyring(con) {
	TemporaryUploadKeyring.super_.call(this, con);

	this._keys = { };
}

util.inherits(TemporaryUploadKeyring, AnonymousKeyring);

pgp.utils.extend(TemporaryUploadKeyring.prototype, {
	_containsKey : function(keyId, callback) {
		callback(null, this._keys[keyId] != null);
	},

	_containsIdentity : function(keyId, identityId, callback) {
		callback(null, this._keys[keyId] != null && this._keys[keyId].identities[identityId] != null);
	},

	_containsAttribute : function(keyId, attributeId, callback) {
		callback(null, this._keys[keyId] != null && this._keys[keyId].attributes[attributeId] != null);
	},

	_onAddKey : function(keyInfo, callback) {
		if(!this._keys[keyInfo.id])
			this._keys[keyInfo.id] = { identities: { }, attributes: { } };

		callback(null);
	},

	_onAddIdentity : function(keyId, identityInfo, callback) {
		if(!this._keys[keyId])
			this._keys[keyId] = { identities: { }, attributes: { } };
		this._keys[keyId].identities[identityInfo.id] = true;

		callback(null);
	},

	_onAddAttribute : function(keyId, attributeInfo, callback) {
		if(!this._keys[keyId])
			this._keys[keyId] = { identities: { }, attributes: { } };
		this._keys[keyId].attributes[attributeInfo.id] = true;

		callback(null);
	}
});

///////////////////////////////////////////////////////////////////////////////

function UserKeyring(con, user) {
	UserKeyring.super_.call(this, con);

	this._user = user;
}

util.inherits(UserKeyring, AnonymousKeyring);

pgp.utils.extend(UserKeyring.prototype, {
	_containsKey : function(keyId, callback) {
		db.entryExists(this._con, "users_keyrings_with_groups_keys", { user: this._user, key: keyId }, callback);
	},

	_containsIdentity : function(keyId, identityId, callback) {
		db.entryExists(this._con, "users_keyrings_with_groups_identities", { user: this._user, identity: identityId, identityKey: keyId }, callback);
	},

	_containsAttribute : function(keyId, attributeId, callback) {
		db.entryExists(this._con, "users_keyrings_with_groups_attributes", { user: this._user, attribute: attributeId, attributeKey: keyId }, callback);
	},

	_onAddKey : function(keyInfo, callback) {
		this._containsKey(keyInfo.id, p(this, function(err, contains) {
			if(err || contains)
				return callback(err);

			db.insert(this._con, "users_keyrings_keys", { user: this._user, key: keyInfo.id }, callback);
		}));
	},

	_onAddIdentity : function(keyId, identityInfo, callback) {
		this._containsIdentity(keyId, identityInfo.id, p(this, function(err, contains) {
			if(err || contains)
				return callback(err);

			db.insert(this._con, "users_keyrings_identities", { user: this._user, identityKey: keyId, identity: identityInfo.id }, callback);
		}));
	},

	_onAddAttribute : function(keyId, attributeInfo, callback) {
		this._containsAttribute(keyId, attributeInfo.id, p(this, function(err, contains) {
			if(err || contains)
				return callback(err);

			db.insert(this._con, "users_keyrings_attributes", { user: this._user, attributeKey: keyId, attribute: attributeInfo.id }, callback);
		}));
	},

	listKeyring : function() {
		return db.getEntries(this._con, "users_keyrings_keys", [ "key" ], { user: this._user }).map(function(it, cb) {
			cb(null, it.key);
		});
	}
});

///////////////////////////////////////////////////////////////////////////////

function GroupKeyring(con, group) {
	GroupKeyring.super_.call(this, con);

	this._group = group;
}

util.inherits(GroupKeyring, AnonymousKeyring);

pgp.utils.extend(GroupKeyring.prototype, {
	_containsKey : function(keyId, callback) {
		db.entryExists(this._con, "groups_keyrings_keys", { group: this._group, key: keyId }, callback);
	},

	_containsIdentity : function(keyId, identityId, callback) {
		db.entryExists(this._con, "groups_keyrings_identities", { group: this._group, identity: identityId, identityKey: keyId }, callback);
	},

	_containsAttribute : function(keyId, attributeId, callback) {
		db.entryExists(this._con, "groups_keyrings_attributes", { group: this._group, attribute: attributeId, attributeKey: keyId }, callback);
	},

	_onAddKey : function(keyInfo, callback) {
		this._containsKey(keyInfo.id, function(err, contains) {
			if(err || contains)
				return callback(err);

			db.insert(this._con, "groups_keyrings_keys", { group: this._group, key: keyInfo.id }, next);
		});
	},

	_onAddIdentity : function(keyId, identityInfo, callback) {
		this._containsIdentity(keyId, identityInfo.id, function(err, contains) {
			if(err || contains)
				return callback(err);

			db.insert(this._con, "groups_keyrings_identities", { group: this._group, identityKey: keyId, identity: identityInfo.id }, callback);
		});
	},

	addAttribute : function(keyId, attributeInfo, callback) {
		this._containsAttribute(keyId, attributeInfo.id, function(err, contains) {
			if(err || contains)
				return callback(err);

			db.insert(this._con, "groups_keyrings_attributes", { group: this._group, attributeKey: keyId, attribute: attributeInfo.id }, callback);
		});
	}
});

///////////////////////////////////////////////////////////////////////////////

exports.UnfilteredKeyring = UnfilteredKeyring;
exports.AnonymousKeyring = AnonymousKeyring;
exports.SearchEngineKeyring = SearchEngineKeyring;
exports.TemporaryUploadKeyring = TemporaryUploadKeyring;
exports.UserKeyring = UserKeyring;
exports.GroupKeyring = GroupKeyring;