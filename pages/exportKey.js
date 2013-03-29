var utils = require("../utils");
var keys = require("../keys");
var pgp = require("node-pgp");
var config = require("../config");

exports.get = function(req, res, next) {
	var keys = req.params.keyId || req.query.key;
	if(!keys)
		return res.redirect(303, config.baseurl+"/keyring");

	utils.checkReferrer(req, res, function(err) {
		if(err)
			return next(err);

		if(req.query.addKey || req.query.remove) {
			req.body.key = keys;
			req.body.addKey = req.query.addKey;
			req.body.remove = req.query.remove;
			return require("./keyring").post(req, res, function(err) {
				if(err)
					return next(err);

				if(req.params.keyId)
					res.redirect(303, config.baseurl+"/key/"+encodeURIComponent(req.params.keyId));
				else
					res.redirect(303, config.baseurl+"/keyring");
			});
		}

		if(!Array.isArray(keys))
			keys = [ keys ];

		var formatInfo = utils.getInfoForFormat(req.query.exportFormat);
		if(keys.length == 1)
			res.attachment("0x"+keys[0]+formatInfo.extension);
		else
			res.attachment("keys"+formatInfo.extension);
		res.type(formatInfo.mimetype);

		var selection = null;

		if(req.query.selection)
		{
			selection = {
				subkeys : { },
				identities : { },
				attributes : { },
				signatures : { }
			};

			for(var i in selection)
			{
				if(!req.query[i])
					continue;
				else if(!Array.isArray(req.query[i]))
					selection[i][req.query[i]] = true;
				else
				{
					req.query[i].forEach(function(it) {
						selection[i][it] = true;
					});
				}
			}
		}

		var streams = [ ];
		for(var i=0; i<keys.length; i++)
			streams.push(req.keyring.exportKey(keys[i], selection));

		utils.encodeToFormat(pgp.BufferedStream.prototype.concat.apply(streams.shift(), streams), req.query.exportFormat).whilst(function(data, cb) {
			res.write(data, "binary");
			cb();
		}, function(err) {
			if(err)
				next(err);
			else
				res.end();
		});
	});
};