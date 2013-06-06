var groups = require("../groups");
var config = require("../config");

exports.get = function(req, res, next) {
	if(!req.session.user)
		return res.redirect(303, config.baseurl+"/login?referer="+encodeURIComponent(req.url));

	groups.getGroupsByUser(req.session.user.id).toArraySingle(function(err, userGroups) {
		if(err)
			return next(err);

		req.params.userGroups = userGroups;

		return next();
	});
};