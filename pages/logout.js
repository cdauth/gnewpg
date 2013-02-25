var sessions = require("../sessions");
var config = require("../config");

module.exports.post = function(req, res, next) {
	sessions.stopSession(req, res, function() {
		res.redirect(303, config.baseurl + (req.query.referer || "/"));
	});
};