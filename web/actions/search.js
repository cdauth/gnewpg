var i18n = require("../../i18n");

module.exports = function(app) {
	app.get("/search", _search);
};

function _search(req, res, next) {
	var now = (new Date()).getTime();

	var params = {
		query : req.query.q || "",
		results : [ ],
		error : null
	};

	if(params.query.length < 3)
	{
		params.error = new i18n.Error_("The search string is too short.");
		return res.soy("search", params);
	}

	req.keyring.search(params.query).forEachSeries(function(it, cb) {
		it.expired = (it.expires && it.expires.getTime() < now);
		params.results.push(it);
		cb();
	}, function(err) {
		if(err)
			params.error = err;
		res.soy("search", params);
	});
}