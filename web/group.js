var groups = require("../groups");
var async = require("async");

exports.get = function(req, res, next) {
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
			groups.getKeysOfGroup(req.params.id).toArraySingle(next);
		},
		render : [ "group", "permission", "membership", "keys", function(next, d) {
			req.params.group = d.group;
			req.params.keys = d.keys;
			req.params.membership = d.membership;

			if(d.group == null || !d.permission) {
				res.status(404);
				req.params.error = req.gettext("Group %s not found.", req.params.id);
			}

			next();
		}]
	}, next);
};