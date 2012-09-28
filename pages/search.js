var keysSearch = require("../keysSearch");
var keyrings = require("../keyrings");

module.exports.get = function(req, res, next) {
	var keyring = null;
	if(req.session.user)
		keyring = keyrings.getKeyringForUser(req.session.user.id);
	
	var now = (new Date()).getTime();

	req.params.query = req.query.q || "";
	req.params.results = [ ];
	req.params.error = null;
	keysSearch.search(req.params.query, keyring).forEachSeries(function(it, cb) {
		it.expired = (it.expires && it.expires.getTime() < now);
		req.params.results.push(it);
		cb();
	}, function(err) {
		if(err)
			req.params.error = err;
		next();
	});
}