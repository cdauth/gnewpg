var groups = require("../../groups");
var async = require("async");
var keyrings = require("../../keyrings");
var keys = require("../../keys");
var config = require("../../config");
var users = require("../../users");
var pgp = require("node-pgp");
var utils = require("../../utils");
var fs = require("fs");
var i18n = require("../../i18n");

var ATTR_MAX_HEIGHT = 50;
var ATTR_MAX_WIDTH = 200;

module.exports = function(app) {
	app.get("/group/:id", _showGroupPage);
	app.get("/group/:id/export", function(req, res, next) {
		if(req.query.join || req.query.leave) {
			utils.checkReferrer(req, res, function(err) {
				if(req.query.join)
					_joinGroup(req, res, next);
				else
					_leaveGroup(req, res, next);
			});
		}
		else
			_exportKeys(req, res, next);
	});
	app.get("/group/:id/settings", _showSettings);
	app.post("/group/:id/settings", _saveSettings);
	app.get("/group/:id/upload", _showUpload);
	app.post("/group/:id/upload", _doUpload);
	app.get("/groups", _showUserGroups);
	app.post("/groups/create", _createGroup);
};

function _joinGroup(req, res, next) {
	async.auto({
		group: function(next) {
			__getGroupAndCheckPermission(req, res, false, next);
		},
		join: [ "group", function(next, d) {
			if(!req.session.user || d.group.membership)
				return next();

			groups.addMember(req.params.id, req.session.user.id, { perm_admin: false, perm_addkeys: false, perm_removekeys: false, list: false }, next);
		} ],
		redirect: [ "join", function(next) {
			res.redirect(303, config.baseurl+"/group/"+encodeURIComponent(req.params.id));
		}]
	}, next);
}

function _leaveGroup(req, res, next) {
	async.auto({
		mayLeaveGroup: function(next) {
			if(req.session.user)
				__mayLeaveGroup(req.params.id, req.session.user.id, next);
			else
				next(null, false);
		},
		leave: [ "mayLeaveGroup", function(next, d) {
			if(d.mayLeaveGroup)
				groups.removeMember(req.params.id, req.session.user.id, next);
			else
				res.redirect(303, config.baseurl+"/group/"+encodeURIComponent(req.params.id));
		}],
		redirect: [ "leave", function(next) {
			res.redirect(303, config.baseurl+"/groups");
		}]
	}, next);
}

function _showGroupPage(req, res, next) {
	async.auto({
		group : function(next) {
			__getGroupAndCheckPermission(req, res, false, next);
		},
		keys : function(next) {
			var groupOnlyKeyring = new keyrings.GroupOnlyKeyring(req.dbCon, req.params.id);
			keys.resolveKeyList(groupOnlyKeyring, groupOnlyKeyring.listKeyring()).toArraySingle(next);
		},
		mayLeaveGroup : function(next) {
			if(!req.session.user)
				next(null, false);
			else
				__mayLeaveGroup(req.params.id, req.session.user.id, next);
		},
		render : [ "group", "keys", "mayLeaveGroup", function(next, d) {
			var params = {
				group : d.group.group,
				keys : d.keys,
				membership : d.group.membership,
				mayLeaveGroup : d.mayLeaveGroup
			};

			res.soy("group", params);
		} ]
	}, next);
}

function _exportKeys(req, res, next) {
	async.auto({
		group: function(next) {
			__getGroupAndCheckPermission(req, res, false, next);
		},
		export: [ "group", function(next, d) {
			if(!req.query.key)
				return res.redirect(303, config.baseurl+"/group/"+encodeURIComponent(req.params.id));

			var groupOnlyKeyring = new keyrings.GroupOnlyKeyring(req.dbCon, req.params.id);
			require("./key").exportKeys(groupOnlyKeyring, req.query.key, d.group.group.title, req, res, next);
		}]
	}, next);
}

function _showSettings(req, res, next) {
	var memberErrors = arguments[3]; // If added as parameter, app.get() does not work anymore

	async.auto({
		group : function(next) {
			__getGroupAndCheckPermission(req, res, true, next);
		},
		members : function(next) {
			groups.getMembers(req.params.id, { list: true }).toArraySingle(next);
		},
		render : [ "group", "members", function(next, d) {
			for(var i=0; i<d.members.length; i++)
				d.members[i].userEncoded = __encodeUsername(d.members[i].user);
			res.soy("groupSettings", { group: d.group.group, members: d.members, memberErrors : memberErrors || [ ] });
		}]
	}, next);
}

function _saveSettings(req, res, next) {
	var groupId = req.params.id;
	var errors = [ ];
	async.auto({
		group : function(next) {
			__getGroupAndCheckPermission(req, res, true, next);
		},
		removeGroup : [ "group", function(next) {
			if(!req.body.removeGroup)
				return next();

			groups.removeGroup(groupId, function(err) {
				if(err)
					return next(err);
				res.redirect(303, config.baseurl+"/groups");
			});
		} ],
		saveSettings : [ "group", "removeGroup", function(next) {
			if(req.body.title == null) // Other Save button has been pressed
				return next();

			groups.updateGroup(groupId, {
				title: req.body.title || "",
				perm_searchengines: req.body.perm_searchengines != null,
				perm_addkeys: req.body.perm_addkeys != null,
				perm_removekeys: req.body.perm_removekeys != null
			}, next);
		} ],
		saveMembers : [ "group", "removeGroup", function(next) {
			var update = Array.isArray(req.body.updateMember) ? req.body.updateMember : req.body.updateMember ? [ req.body.updateMember ] : [ ];

			var addName = Array.isArray(req.body.addMember) ? req.body.addMember : req.body.addMember ? [ req.body.addMember ] :  [ ];
			var addAdmin = Array.isArray(req.body.addMember_perm_admin) ? req.body.addMember_perm_admin : [ req.body.addMember_perm_admin ];
			var addAddkeys = Array.isArray(req.body.addMember_perm_addkeys) ? req.body.addMember_perm_addkeys : [ req.body.addMember_perm_addkeys ];
			var addRemovekeys = Array.isArray(req.body.addMember_perm_removekeys) ? req.body.addMember_perm_removekeys : [ req.body.addMember_perm_removekeys ];
			for(var i=0; i<addName.length; i++) {
				var enc = __encodeUsername(addName[i]);
				update.push(enc);
				req.body["perm_admin-"+enc] = addAdmin[i];
				req.body["perm_addkeys-"+enc] = addAddkeys[i];
				req.body["perm_removekeys-"+enc] = addRemovekeys[i];
			}

			async.forEachSeries(update, function(enc, next) {
				var username = __decodeUsername(enc).trim();
				if(username == "")
					return next();

				async.auto({
					exists : function(next) {
						users.userExists(req.dbCon, username, next);
					},
					isMember : function(next) {
						groups.getMemberSettings(groupId, username, next);
					},
					addOrUpdate : [ "exists", "isMember", function(next, d) {
						var settings;
						if(req.body["remove-"+enc] && username != req.session.user.id)
							settings = { perm_admin: false, perm_addkeys: false, perm_removekeys: false, list: false };
						else
							settings = { perm_admin: username == req.session.user.id || !!req.body["perm_admin-"+enc], perm_addkeys: !!req.body["perm_addkeys-"+enc], perm_removekeys: !!req.body["perm_removekeys-"+enc], list: true };

						if(!d.exists) {
							errors.push(req.gettext("User %s does not exist.", username));
							next();
						} else if(!d.isMember)
							groups.addMember(groupId, username, settings, next);
						else
							groups.updateMember(groupId, username, settings, next);
					} ]
				}, next);
			}, next);
		} ],
		render : [ "saveSettings", "saveMembers", "removeGroup", function(next, d) {
			_showSettings(req, res, next, errors);
		} ]
	}, next);
}

function _showUserGroups(req, res, next) {
	if(!req.session.user)
		return res.redirect(303, config.baseurl+"/login?referer="+encodeURIComponent(req.url));

	groups.getGroupsByUser(req.session.user.id).toArraySingle(function(err, userGroups) {
		if(err)
			return next(err);

		res.soy("groups", { userGroups: userGroups });
	});
}

function _createGroup(req, res, next) {
	if(!req.session.user)
		return res.redirect(303, config.baseurl+"/login?referer="+encodeURIComponent(req.url));

	groups.createGroup(function(err, groupOptions) {
		if(err)
			return next(err);

		groups.addMember(groupOptions.id, req.session.user.id, { perm_admin: true, perm_addkeys: true, perm_removekeys: true, list: true }, function(err) {
			if(err)
				return next(err);

			res.redirect(303, config.baseurl+"/group/"+encodeURIComponent(groupOptions.id));
		});
	});
}

function _showUpload(req, res, next) {
	async.auto({
		group: function(next) {
			__getGroupAndCheckPermission(req, res, false, next);
		},
		permissions : [ "group", function(next, d) {
			if(!d.group.group.perm_addkeys && !d.group.group.perm_removekeys && (!d.group.membership || !d.group.membership.perm_addkeys && !d.group.membership.perm_removekeys))
				return res.sendError(403, req.gettext("No permission to add/remove keys"));
			next();
		} ],
		userKeyring : [ "permissions", function(next) {
			if(!req.session.user)
				return next(null, null);

			keys.getKeysOfUser(req.dbCon, req.session.user.id).toArraySingle(function(err, ownKeyIds) {
				if(err)
					return next(err);

				var ownKeys = keys.resolveKeyList(req.keyring, pgp.Fifo.fromArraySingle(ownKeyIds)).map(function(it, next) {
					it.own = true;
					next(null, it);
				});

				var otherKeyIds = req.keyring.listKeyring().grep(function(it, next) {
					next(null, ownKeyIds.indexOf(it) == -1);
				});
				var otherKeys = keys.resolveKeyList(req.keyring, otherKeyIds);

				__addSubObjectsToKeyList(req.keyring, ownKeys.concat(otherKeys)).toArraySingle(next);
			});
		} ],
		groupKeyring : [ "permissions", function(next) {
			var groupOnlyKeyring = new keyrings.GroupOnlyKeyring(req.dbCon, req.params.id);
			__addSubObjectsToKeyList(groupOnlyKeyring, keys.resolveKeyList(groupOnlyKeyring, groupOnlyKeyring.listKeyring())).toArraySingle(next);
		} ],
		render : [ "group", "permissions", "userKeyring", "groupKeyring", function(next, d) {
			res.soy("groupUpload", {
				group: d.group.group,
				addkeys: d.group.group.perm_addkeys || (d.group.membership && d.group.membership.perm_addkeys),
				removekeys: d.group.group.perm_removekeys || (d.group.membership && d.group.membership.perm_removekeys),
				userKeyring: d.userKeyring,
				groupKeyring: d.groupKeyring
			});
		} ]
	}, next);
}

function _doUpload(req, res, next) {
	var f = req.files && req.files.file ? Array.isArray(req.files.file) ? req.files.file : [ req.files.file ] : [ ];
	var params = {
		uploadedKeys : [ ],
		errors : [ ],
		failed : [ ],
		group : [ ]
	};
	var groupKeyring = new keyrings.GroupOnlyKeyring(req.dbCon, req.params.id);

	async.auto({
		group: function(next) {
			__getGroupAndCheckPermission(req, res, false, next);
		},
		permissions : [ "group", function(next, d) {
			var permAdd = (d.group.group.perm_addkeys || (d.group.membership && d.group.membership.perm_addkeys));
			var permRemove = (d.group.group.perm_removekeys || (d.group.membership && d.group.membership.perm_removekeys));
			if(!permAdd && !permRemove)
				return res.sendError(403, req.gettext("No permission to add/remove keys"));
			next(null, { add: permAdd, remove: permRemove });
		} ],
		uploadFiles : [ "permissions", function(next, d) {
			if(!d.permissions.add)
				return next();

			async.forEachSeries(f, function(it, next) {
				groupKeyring.importKeys(fs.createReadStream(it.path), function(err, uploaded) {
					if(err)
					{
						console.warn("Error while uploading key", err);
						params.errors.push(err);
					}
					else
					{
						params.uploadedKeys = params.uploadedKeys.concat(uploaded.keys);
						params.failed = params.failed.concat(uploaded.failed);
					}

					fs.unlink(it.path, function(err) {
						if(err)
							console.warn("Error removing uploaded key file", err);

						next();
					});
				});
			}, next);
		} ],
		importPasted : [ "permissions", function(next, d) {
			if(!d.permissions.add)
				return next();

			groupKeyring.importKeys(req.body.paste || "", function(err, uploaded) {
				if(err)
				{
					console.warn("Error while uploading key", err);
					params.errors.push(err);
				}
				else
				{
					params.uploadedKeys = params.uploadedKeys.concat(uploaded.keys);
					params.failed = params.failed.concat(uploaded.failed);
				}

				next();
			});
		} ],
		addFromKeyring : [ "permissions", function(next, d) {
			if(!d.permissions.add)
				return next();

			async.forEachSeries(utils.normaliseArrayParam(req.body["keyring-keys"]), function(keyId, next) {
				var addedKey = { type : pgp.consts.PKT.PUBLIC_KEY, id : keyId, identities: [ ], attributes: [ ] };
				async.auto({
					keyExists : function(next) {
						req.keyring.keyExists(keyId, next);
					},
					addKey : [ "keyExists", function(next2, d) {
						if(d.keyExists) {
							params.uploadedKeys.push(addedKey);
							groupKeyring.addKeyToKeyring(keyId, next2);
						} else {
							params.failed.push(pgp.utils.extend(addedKey, { err: new i18n.Error_('Key %s not found.', keyId) }));
							next();
						}
					}],
					addIdentities : [ "addKey", function(next) {
						async.forEachSeries(utils.normaliseArrayParam(req.body["keyring-identities-"+keyId]), function(identityId, next) {
							req.keyring.identityExists(keyId, identityId, function(err, exists) {
								if(err)
									return next(err);
								else if(!exists) {
									params.failed.push({ type: pgp.consts.PKT.USER_ID, id: identityId, err: new i18n.Error_('Identity %s not found.', identityId) });
									next();
								} else {
									addedKey.identities.push({ type: pgp.consts.PKT.USER_ID, id: identityId });
									groupKeyring.addIdentityToKeyring(keyId, identityId, next);
								}
							});
						}, next);
					} ],
					addAttributes : [ "addKey", function(next) {
						async.forEachSeries(utils.normaliseArrayParam(req.body["keyring-attributes-"+keyId]), function(attributeId, next) {
							req.keyring.attributeExists(keyId, attributeId, function(err, exists) {
								if(err)
									return next(err);
								else if(!exists) {
									params.failed.push({ type: pgp.consts.PKT.ATTRIBUTE, id: attributeId, err: new i18n.Error_('Attribute not found.') });
									next();
								} else {
									addedKey.attributes.push({ type: pgp.consts.PKT.ATTRIBUTE, id: attributeId });
									groupKeyring.addAttributeToKeyring(keyId, attributeId, next);
								}
							});
						}, next);
					} ]
				}, next);
			}, next);
		} ],
		remove : [ "permissions", function(next, d) {
			if(!d.permissions.remove)
				return next();

			var removeKeys = utils.normaliseArrayParam(req.body["remove-keys"]);
			groupKeyring.listKeyring().forEachSeries(function(keyId, next) {
				async.auto({
					removeIdentities: function(next) {
						async.forEachSeries(utils.normaliseArrayParam(req.body["remove-identities-"+keyId]), function(identityId, next) {
							groupKeyring.removeIdentityFromKeyring(keyId, identityId, next);
						}, next);
					},
					removeAttributes: function(next) {
						async.forEachSeries(utils.normaliseArrayParam(req.body["remove-attributes-"+keyId]), function(attributeId, next) {
							groupKeyring.removeAttributeFromKeyring(keyId, attributeId, next);
						}, next);
					},
					removeKey: function(next) {
						if(removeKeys.indexOf(keyId) != -1)
							groupKeyring.removeKeyFromKeyring(keyId, next);
						else
							next();
					}
				}, next);
			}, next);
		}]
	}, function(err, d) {
		if(err) {
			return groupKeyring.revertChanges(function() {
				next(err);
			});
		}

		groupKeyring.saveChanges(function(err) {
			if(err)
				next(err);
			else {
				params.group = d.group.group;

				for(var i=0; i<params.failed.length; i++)
				{
					if(params.failed[i].type == pgp.consts.PKT.RING_TRUST)
					{
						params.failed = params.failed.slice(0, i).concat(params.failed.slice(i+1));
						i--;
					}
				}

				if(params.failed.length == 0 && params.uploadedKeys.length == 0 && params.errors.length == 0)
					res.redirect(303, config.baseurl+'/group/'+encodeURIComponent(req.params.id)+(req.query.groupToken ? "?groupToken="+encodeURIComponent(req.query.groupToken) : ""));
				else
					res.soy("groupUploaded", params);
			}
		});
	});
}

function __encodeUsername(username) {
	return new Buffer(username).toString("base64").replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function __decodeUsername(username) {
	return new Buffer(username.replace(/-/g, '+').replace(/_/g, '/'), "base64").toString();
}

function __mayLeaveGroup(groupId, username, callback) {
	groups.getMembers(groupId, { perm_admin: true, user: new pgp.Keyring.Filter.Not(new pgp.Keyring.Filter.Equals(username)) }).forEachSeries(function(it, next) {
		callback(null, true);
	}, function(err) {
		callback(err, false);
	});
}

function __getGroupAndCheckPermission(req, res, forceAdmin, callback) {
	if(forceAdmin && !req.session.user)
		return res.redirectLogin();

	groups.getGroup(req.params.id, function(err, groupInfo) {
		if(err)
			return callback(err);

		if(groupInfo == null)
			return res.sendError(404, req.gettext("Group %s not found.", req.params.id));

		req.keyring.maySeeGroup(req.params.id, function(err, maySeeGroup) {
			if(err)
				return callback(err);

			if(!maySeeGroup)
				return res.sendError(404, req.gettext("Group %s not found.", req.params.id));

			if(!req.session.user)
				return callback(null, { group: groupInfo, membership: null });

			groups.getMemberSettings(req.params.id, req.session.user.id, function(err, memberSettings) {
				if(err)
					return callback(err);

				if(forceAdmin && (memberSettings == null || !memberSettings.perm_admin))
					return res.sendError(403, req.gettext("No access."));

				callback(null, { group: groupInfo, membership: memberSettings });
			});
		});
	});
}

function __addSubObjectsToKeyList(keyring, keyList) {
	return keyList.map(function(it, next) {
		keyring.getSelfSignedIdentities(it.id, null, [ "id", "name", "email", "nameTrust", "emailTrust" ]).toArraySingle(function(err, identities) {
			if(err)
				return next(err);

			it.identities = identities;
			it.attributes = [ ];
			keyring.getSelfSignedAttributes(it.id, null, [ "id", "subPackets", "trust" ]).forEachSeries(function(attributeInfo, next) {
				var attrs = pgp.utils.extend([ ], attributeInfo);

				it.attributes.push(attrs);

				async.forEachSeries(attributeInfo.subPackets, function(subPacket, next) {
					if(subPacket.type != pgp.consts.ATTRSUBPKT.IMAGE || subPacket.imageType != pgp.consts.IMAGETYPE.JPEG)
						return next();

					utils.scaleImage(subPacket.image, ATTR_MAX_WIDTH, ATTR_MAX_HEIGHT, function(err, scaleImg, width, height) {
						if(err)
							return next(err);

						attrs.push("data:image/jpeg;base64,"+scaleImg.toString("base64"));
						next();
					});
				}, next);
			}, function(err) {
				next(err, it);
			});
		});
	});
}