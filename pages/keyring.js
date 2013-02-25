var keys = require("../keys");
var config = require("../config");

exports.get = function(req, res, next) {
	if(!req.session.user)
	{
		res.redirect(303, config.baseurl+"/login?referer="+encodeURIComponent(req.url));
		return;
	}

	keys.resolveKeyList(req.keyring, req.keyring.listKeyring()).toArraySingle(function(err, keyList) {
		if(err)
			return next(err);

		req.params.keys = keyList;
		next();
	});
};