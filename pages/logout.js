var sessions = require("../sessions");

module.exports.post = function(req, res, next) {
	sessions.stopSession(req, res, function() {
		res.redirect(303, req.query.referer || "/");
	});
};