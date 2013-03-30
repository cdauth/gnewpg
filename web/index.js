var config = require("../config");

exports.get = function(req, res, next) {
	if(req.session.user)
		req.params.keyserver = "hkps://"+config.personalHkpHostname.replace("%s", req.session.user.secret);
	else
		req.params.keyserver = "hkps://"+config.hkpHostname;

	next();
};