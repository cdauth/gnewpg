var keys = require("../keys");

exports.get = function(req, res, next) {
	if(!req.session.user)
	{
		res.redirect(303, "/login?referer="+encodeURIComponent(req.url));
		return;
	}

	keys.resolveKeyList(req.keyring, req.keyring.listKeyring()).toArraySingle(function(err, keyList) {
		if(err)
			req.params.error = err;
		else
			req.params.keys = keyList;

		next();
	});
};