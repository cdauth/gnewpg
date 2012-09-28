var utils = require("../utils");
var keyrings = require("../keyrings");
var keys = require("../keys");

exports.get = function(req, res, next) {
	var formatInfo = utils.getInfoForFormat(req.query.exportFormat);
	res.attachment("0x"+req.params.keyId+formatInfo.extension);
	res.type(formatInfo.mimetype);
	
	var keyring = null;
	if(req.session.user)
		keyring = keyrings.getKeyringForUser(req.session.user.id);
	
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
	
	utils.encodeToFormat(keys.exportKey(req.params.keyId, keyring, selection), req.query.exportFormat).whilst(function(data, cb) {
		res.write(data, "binary");
		cb();
	}, function(err) {
		if(err)
			next(err);
		else
			res.end();
	});
}