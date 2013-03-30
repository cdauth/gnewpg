var sessions = require("../sessions");
var utils = require("../utils");
var db = require("../database");
var users = require("../users");
var config = require("../config");
var openid = require("openid");

var relyingParty = new openid.RelyingParty(config.baseurl+"/login?openid_verify=1");

module.exports.get = module.exports.post = function(req, res, next) {
	if(req.session.user)
		return res.redirect(303, config.baseurl + (req.query.referer || "/"));

	if(req.query.stayloggedin) // For OpenID logins
		req.body.stayloggedin = req.query.stayloggedin;

	req.params.username = req.body.username;
	req.params.openid = req.body.openid;
	req.params.stayloggedin = req.body.stayloggedin;

	if(req.body.openid) {
		req.body.openid = req.body.openid.trim();

		users.getUserByOpenId(req.dbCon, req.body.openid, function(err, user) {
			if(err)
				return next(err);

			if(user == null) {
				req.params.openidErrors = [ req.gettext("There is no user account with this OpenID.") ];
				return next();
			}

			new openid.RelyingParty(config.baseurl+"/login?openid_verify=1"+(req.body.stayloggedin ? "&stayloggedin=1" : "")+"&referer="+encodeURIComponent(req.query.referer)).authenticate(req.body.openid, false, function(err, url) {
				if(url)
					return res.redirect(303, url);

				if(err)
					req.params.openidErrors = [ req.gettext("OpenID authentication failed: %s", err.message) ];
				else
					req.params.openidErrors = [ req.gettext("OpenID authentication failed.") ];
				next();
			});
		});
	}
	else if(req.query.openid_verify) {
		// TODO: Somehow avoid Login CSRF? We cannot check the Referer, as that is set to the OpenID
		// provider’s login page.

		relyingParty.verifyAssertion(req, function(err, verified) {
			if(err)
				req.params.openidErrors = [ req.gettext("Error verifying openid: %s", err.message) ];
			else if(!verified.authenticated)
				req.params.openidErrors = [ req.gettext("Error verifying openid.") ];
			else {
				return users.getUserByOpenId(req.dbCon, verified.claimedIdentifier, function(err, user) {
					if(err)
						return next(err);

					if(user == null)
						req.params.openidErrors = [ req.gettext("There is no user account with this OpenID.") ];
					else
						return login(user);

					next();
				});
			}

			next();
		});
	}
	else if(req.method == "POST") {
		users.getUser(req.dbCon, req.body.username || "", function(err, user) {
			if(err)
				next(err);
			else if(user != null && user.password == utils.encodePassword(req.body.password || ""))
				login(user);
			else
			{
				req.params.errors = [ req.gettext("Login failed.") ];
				next();
			}
		});
	}
	else
		next();

	function login(user) {
		sessions.startSession(req, res, user, req.body.stayloggedin != null, function(err) {
			if(err)
				next(err);
			else
			{
				res.redirect(303, config.baseurl + (req.query.referer || "/"));
				next();
			}
		});
	}
};