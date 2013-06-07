var groups = require("../../groups");
var async = require("async");
var keyrings = require("../../keyrings");
var keys = require("../../keys");
var config = require("../../config");

module.exports = function(app) {
	app.get("/group/:id", function(req, res, next) {
		if(req.query.join || req.query.leave) {
			utils.checkReferrer(req, res, function(err) {
				if(req.query.join)
					_joinGroup(req, res, next);
				else
					_leaveGroup(req, res, next);
			});
		}
		else
			_showGroupPage(req, res, next);
	});

	app.get("/group/:id/export", _exportKeys);
	app.get("/group/:id/settings", _showSettings);
	app.post("/group/:id/settings", _saveSettings);
	app.get("/group/:id/upload", _showUpload);
	app.get("/groups", _showUserGroups);
	app.post("/groups/create", _createGroup);
};

function _joinGroup(req, res, next) {

}

function _leaveGroup(req, res, next) {

}

function _showGroupPage(req, res, next) {
	async.auto({
		group : function(next) {
			groups.getGroup(req.params.id, next);
		},
		membership : function(next) {
			if(!req.session.user)
				return next(null, null);

			groups.getMemberSettings(req.params.id, req.session.user.id, next);
		},
		permission : function(next) {
			req.keyring.maySeeGroup(req.params.id, next);
		},
		keys : function(next) {
			keys.resolveKeyList(req.keyring, new keyrings.GroupKeyring(req.dbCon, req.params.id).listKeyring()).toArraySingle(next);
		},
		render : [ "group", "permission", "membership", "keys", function(next, d) {
			var params = {
				group : d.group,
				keys : d.keys,
				membership : d.membership
			};

			if(d.group == null || !d.permission) {
				res.status(404);
				params.error = req.gettext("Group %s not found.", req.params.id);
			}

			res.soy("group", params);
		}]
	}, next);
};

function _exportKeys(req, res, next) {
	async.auto({
		group: function(next) {
			groups.getGroup(req.params.id, next);
		},
		permission: function(next) {
			req.keyring.maySeeGroup(req.params.id, next);
		},
		keys: function(next) {
			groups.getKeysOfGroup(req.params.id).toArraySingle(next);
		},
		export: [ "permission", "keys", function(next, d) {
			if(!d.group || !d.permission)
				res.send(404, req.gettext("Group %s not found.", req.params.id));

			require("./exportKey").exportKeys(req.keyring, req.query.key, d.group.title, req, res, next);
		}]
	}, next);
};

function _showSettings(req, res, next) {
	async.auto({
		group : function(next) {
			groups.getGroup(req.params.id, next);
		},
		membership : function(next) {
			if(!req.session.user)
				return next(null, null);

			groups.getMemberSettings(req.params.id, req.session.user.id, next);
		},
		render : [ "group", "membership", function(next, d) {
			if(d.group == null || d.membership == null || !d.membership.perm_admin) {
				if(!req.session.user)
					return res.redirectLogin();
				else
					return res.redirect(303, config.baseUrl+"/group/"+req.params.id);
			}

			res.soy("groupSettings", { group: d.group });
		}]
	}, next);
};

function _saveSettings(req, res, next) {
	async.auto({
		membership : function(next) {
			if(!req.session.user)
				return next(null, null);

			groups.getMemberSettings(req.params.id, req.session.user.id, next);
		},
		save : [ "membership", function(next, d) {
			if(d.membership == null || !d.membership.perm_admin)
				return res.send(403, req.gettext("No access."));

			groups.updateGroup(req.params.id, {
				title: req.body.title || "",
				perm_searchengines: req.body.perm_searchengines != null,
				perm_addkeys: req.body.perm_addkeys != null,
				perm_removekeys: req.body.perm_removekeys != null
			}, next);
		} ],
		render : [ "save", function(next) {
			_showSettings(req, res, next);
		}]
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

		groups.addUserToGroup(groupOptions.id, req.session.user.id, function(err) {
			if(err)
				return next(err);

			res.redirect(303, config.baseurl+"/group/"+encodeURIComponent(groupOptions.id));
		}, true);
	});
}

function _showUpload(req, res, next) {

}