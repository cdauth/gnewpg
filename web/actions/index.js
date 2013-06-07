var config = require("../../config");

module.exports = function(app) {
	app.get("/", _renderIndex);
	app.get("/faq/:no", _renderFaq);
};

function _renderIndex(req, res, next) {
	var params = { keyserver: null };

	if(config.hkpHostname) {
		if(req.session.user)
			params.keyserver = "hkps://"+config.personalHkpHostname.replace("%s", req.session.user.secret);
		else
			params.keyserver = "hkps://"+config.hkpHostname;
	}

	res.soy("index", params);
}

function _renderFaq(req, res, next) {
	res.soy("faq", { no: req.params.no });
}