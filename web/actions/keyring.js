var keys = require("../../keys");
var config = require("../../config");
var pgp = require("node-pgp");
var utils = require("../../utils");

module.exports = function(app) {
	app.get("/keyring", _showKeyring);
	app.get("/keyring/export", function(req, res, next) {
		if(req.query.addKey || req.query.remove) {
			utils.checkReferrer(req, res, function(err) {
				if(err)
					return next(err);

				req.body.key = req.query.key;
				req.body.addKey = req.query.addKey;
				req.body.remove = req.query.remove;

				_addRemoveKeys(req, res, next);
			});
		}
		else
			_exportKeyring(req, res, next);
	});
};

function _showKeyring(req, res, next) {
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

			res.soy("keyring", { keys: keyList });
		});
	});
}

function _addRemoveKeys(req, res, next) {
	var keys = req.body.key;
	if(!Array.isArray(keys))
		keys = [ keys ];

	if(req.body.remove) {
		req.keyring.removeFromKeyring(keys, function(err) {
			if(err)
				return next(err);

			res.redirect(303, config.baseurl+"/keyring");
		});
	} else {
		req.keyring.addToKeyring(keys, function(err) {
			if(err)
				return next(err);

			res.redirect(303, config.baseurl+"/keyring");
		});
	}
}

function _exportKeyring(req, res, next) {
	if(!req.query.key)
		return res.redirect(303, config.baseurl+"/keyring");

	require("./key").exportKeys(req.keyring, req.query.key, null, req, res, next);
}