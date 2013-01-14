var sessions = require("../sessions");
var utils = require("../utils");
var db = require("../database");
var users = require("../users");

module.exports.get = function(req, res, next) {
	if(req.session.user)
		res.redirect(303, req.query.referer || "/");
	else
		next();
};

module.exports.post = function(req, res, next) {
	req.params.username = req.body.username;

	users.getUser(req.dbCon, req.body.username || "", function(err, user) {
		if(err)
			next(err);
		else if(user != null && user.password == utils.encodePassword(req.body.password || ""))
		{
			sessions.startSession(req, res, user, req.body.stayloggedin != null, function(err) {
				if(err)
					next(err);
				else
				{
					res.redirect(303, req.query.referer || "/");
					next();
				}
			});
		}
		else
		{
			req.params.errors = [ req.gettext("Login failed.") ];
			next();
		}
	});
};