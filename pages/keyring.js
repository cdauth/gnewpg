var db = require("../database");
var keys = require("../keys");
var keyrings = require("../keyrings");

exports.get = function(req, res, next) {
	if(!req.session.user)
	{
		res.redirect(303, "/login?referer="+encodeURIComponent(req.url));
		return;
	}
	
	var keyring = keyrings.getKeyringForUser(req.session.user.id);

	var keyringKeys = [ ];
	db.getEntriesSync("users_keyrings_keys_with_keys", [ "id", "expires", "revokedby" ], { user: req.session.user.id }).forEachSeries(function(keyringRecord, cb) {
		keyringKeys.push(keyringRecord);
		
		keyringRecord.expired = (keyringRecord.expires && keyringRecord.expires.getTime() <= (new Date()).getTime());
		
		keys.getPrimaryIdentity(keyringRecord.id, keyring, function(err, primaryIdRecord) {
			if(err)
				cb(err);
			else
			{
				keyringRecord.primary_identity = primaryIdRecord;
				cb();
			}
		});
	}, function(err) {
		if(err)
			req.params.error = err;
		else
			req.params.keys = keyringKeys;
		next()
	});
}