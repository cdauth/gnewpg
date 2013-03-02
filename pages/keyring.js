var keys = require("../keys");
var config = require("../config");
var pgp = require("node-pgp");

exports.get = function(req, res, next) {
	if(!req.session.user)
	{
		res.redirect(303, config.baseurl+"/login?referer="+encodeURIComponent(req.url));
		return;
	}

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

		ownKeys.concat(otherKeys).toArraySingle(function(err, keyList) {
			if(err)
				return next(err);

			req.params.keys = keyList;
			next();
		});
	});
};