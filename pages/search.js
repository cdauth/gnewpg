var i18n = require("../i18n");

module.exports.get = function(req, res, next) {
	var now = (new Date()).getTime();

	req.params.query = req.query.q || "";
	req.params.results = [ ];
	req.params.error = null;

	if(req.params.query.length < 3)
	{
		req.params.error = new i18n.Error_("The search string is too short.");
		return next();
	}

	req.keyring.search(req.params.query).forEachSeries(function(it, cb) {
		it.expired = (it.expires && it.expires.getTime() < now);
		req.params.results.push(it);
		cb();
	}, function(err) {
		if(err)
			req.params.error = err;
		next();
	});
}