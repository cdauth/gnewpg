var groups = require("../groups");
var config = require("../config");

exports.post = function(req, res, next) {
	if(!req.session.user)
		return res.redirect(303, config.baseurl+"/login?referer="+encodeURIComponent(req.url));

	groups.createGroup(req.gettext("Unnamed group"), function(err, groupOptions) {
		if(err)
			return next(err);

		groups.addUserToGroup(groupOptions.id, req.session.user.id, function(err) {
			if(err)
				return next(err);

			res.redirect(303, config.baseurl+"/group/"+encodeURIComponent(groupOptions.id));
		}, true);
	})
};