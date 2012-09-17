var users = require("../users");
var sessions = require("../sessions");

module.exports.get = function(req, res, next) {
	if(req.session.user)
		res.redirect(303, req.query.referer || "/");
	else
		next();
};

module.exports.post = function(req, res, next) {
	req.params.username = req.body.username;

	users.getUser(req.body.username || "", function(user) {
		if(user != null && users.checkPassword(user, req.body.password || ""))
		{
			sessions.startSession(req, res, user, req.body.stayloggedin != null, function() {
				res.redirect(303, req.query.referer || "/");
			});
		}
		else
		{
			req.params.errors = [ req.gettext("Login failed.") ];
			next();
		}
	});
};