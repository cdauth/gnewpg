var sessions = require("../../sessions");
var utils = require("../../utils");
var db = require("../../database");
var users = require("../../users");
var config = require("../../config");
var openid = require("openid");
var async = require("async");
var i18n = require("../../i18n");
var keys = require("../../keys");

var relyingPartyLogin = new openid.RelyingParty(config.baseurl+"/login?openid_verify=1");

module.exports = function(app) {
	app.get("/login", _doLogin);
	app.post("/login", _doLogin);
	app.post("/logout", _doLogout);
	app.get("/register", _showRegistrationForm);
	app.post("/register", _doRegister);
	app.get("/settings", _userSettings);
	app.post("/settings", _userSettings);
};

function _doLogin(req, res, next) {
	if(req.session.user)
		return res.redirect(303, config.baseurl + (req.query.referer || "/"));

	if(req.query.stayloggedin) // For OpenID logins
		req.body.stayloggedin = req.query.stayloggedin;

	var params = { };

	params.username = req.body.username;
	params.openid = req.body.openid;
	params.stayloggedin = req.body.stayloggedin;

	if(req.body.openid) {
		req.body.openid = req.body.openid.trim();

		users.getUserByOpenId(req.dbCon, req.body.openid, function(err, user) {
			if(err)
				return next(err);

			if(user == null) {
				params.openidErrors = [ req.gettext("There is no user account with this OpenID.") ];
				return res.soy("login", params);
			}

			new openid.RelyingParty(config.baseurl+"/login?openid_verify=1"+(req.body.stayloggedin ? "&stayloggedin=1" : "")+"&referer="+encodeURIComponent(req.query.referer)).authenticate(req.body.openid, false, function(err, url) {
				if(url)
					return res.redirect(303, url);

				if(err)
					params.openidErrors = [ req.gettext("OpenID authentication failed: %s", err.message) ];
				else
					params.openidErrors = [ req.gettext("OpenID authentication failed.") ];
				res.soy("login", params)
			});
		});
	}
	else if(req.query.openid_verify) {
		// TODO: Somehow avoid Login CSRF? We cannot check the Referer, as that is set to the OpenID
		// provider’s login page.

		relyingPartyLogin.verifyAssertion(req, function(err, verified) {
			if(err)
				params.openidErrors = [ req.gettext("Error verifying openid: %s", err.message) ];
			else if(!verified.authenticated)
				params.openidErrors = [ req.gettext("Error verifying openid.") ];
			else {
				return users.getUserByOpenId(req.dbCon, verified.claimedIdentifier, function(err, user) {
					if(err)
						return next(err);

					if(user == null)
						params.openidErrors = [ req.gettext("There is no user account with this OpenID.") ];
					else
						return login(user);

					res.soy("login", params)
				});
			}

			res.soy("login", params)
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
				params.errors = [ req.gettext("Login failed.") ];
				res.soy("login", params)
			}
		});
	}
	else
		res.soy("login", params)

	function login(user) {
		sessions.startSession(req, res, user, req.body.stayloggedin != null, function(err) {
			if(err)
				next(err);
			else
				res.redirect(303, config.baseurl + (req.query.referer || "/"));
		});
	}
}

function _doLogout(req, res, next) {
	sessions.stopSession(req, res, function() {
		res.redirect(303, config.baseurl + (req.query.referer || "/"));
	});
}

function _showRegistrationForm(req, res, next) {
	res.soy("register");
}

function _doRegister(req, res, next) {
	var params = { errors: [ ] };

	if(req.body.username)
		req.body.username = req.body.username.trim();
	if(req.body.email)
		req.body.email = req.body.email.trim() || null;

	if(!req.body.username || req.body.username.length < config.usernameMinLength)
		params.errors.push(req.ngettext("The username has to be at least %d character long.", "The username has to be at least %d characters long.", config.usernameMinLength, config.usernameMinLength));
	else if(req.body.username.length > config.usernameMaxLength)
		params.errors.push(req.ngettext("The username may be at most %d character long.", "The username may be at most %d characters long.", config.usernameMaxLength, config.usernameMaxLength));

	users.userExists(req.dbCon, req.body.username, function(err, exists) {
		if(err)
			next(err);
		else
		{
			if(exists)
				params.errors.push(req.gettext("This username is already taken."));
			if(!req.body.password || req.body.password.length < config.passwordMinLength)
				params.errors.push(req.ngettext("The password has to be at least %d character long.", "The password has to be at least %d characters long.", config.passwordMinLength, config.passwordMinLength));
			else if(req.body.password != req.body.password2)
				params.errors.push(req.gettext("The two passwords do not match."));

			if(params.errors.length == 0)
			{
				users.createUser(req.dbCon, req.body.username, req.body.password, req.body.email, null, req.locale, function(err) {
					if(err)
						next(err);
					else
					{
						params.success = true;
						res.soy("register", params);
					}
				});
			}
			else
			{
				params.username = req.body.username;
				params.email = req.body.email;
				res.soy("register", params);
			}
		}
	});
}

function _userSettings(req, res, next) {
	// Not logged in: cannot edit settings
	if(!req.session.user)
		return res.redirectLogin();

	var params = { errors: [ ] };
	var update = { };
	async.series([
		function(next) {
			keys.resolveKeyList(req.keyring, keys.getKeysOfUser(req.dbCon, req.session.user.id)).toArraySingle(function(err, ownKeys) {
				if(err)
					return next(err);

				params.ownKeys = ownKeys;
				next();
			});
		},
		function(next) {
			if(req.method == "POST")
			{
				if((req.body.password && req.body.password.length > 0) || (req.body.password2 && req.body.password2.length > 0))
				{
					if(!req.body.password || req.body.password.length < config.passwordMinLength)
						params.errors.push(req.ngettext("The password has to be at least %d character long.", "The password has to be at least %d characters long.", config.passwordMinLength, config.passwordMinLength));
					else if(req.body.password != req.body.password2)
						params.errors.push(req.gettext("The two passwords do not match."));
					else
						update.password = utils.encodePassword(req.body.password);
				}

				if(req.body.email)
					update.email = req.body.email;

				if(req.body.locale)
					update.locale = req.body.locale;

				if(req.body.mainkey != null)
					update.mainkey = (req.body.mainkey == "" ? null : req.body.mainkey);
			}

			if(req.query.openid_verify)
			{
				relyingParty.verifyAssertion(req, function(err, res) {
					if(err)
						params.errors.push(req.gettext("Error verifying openid: %s", err.message));
					else if(!res.authenticated || res.claimedIdentifier != req.session.user.newOpenid)
						params.errors.push(req.gettext("Error verifying openid."));
					else
						update.openid = res.claimedIdentifier;
					// TODO: Maybe check if openid is already used by different account? At the moment
					// this is enforced by the UNIQUE constraint.
					next();
				});
				return;
			}

			next();
		},
		function(next) {
			if(req.method == "POST" && req.body.openid != null) {
				req.body.openid = req.body.openid.trim();

				if(req.body.openid == "") {
					update.openid = null;
					update.newOpenid = null;
				}
				else if(req.body.openid != req.session.user.openid) {
					return users.getUserByOpenId(req.dbCon, req.body.openid, function(err, user) {
						if(err)
							return next(err);

						if(user != null)
							params.errors.push(req.gettext("This OpenID is used by another account already."));
						else
							update.newOpenid = req.body.openid;

						next();
					});
				}
			}

			next();
		},
		function(next) {
			if(Object.keys(update).length > 0)
			{
				params.updated = true;
				users.updateUser(req.dbCon, req.session.user.id, update, next);
			}
			else
				next();
		},
		function(next) {
			users.getUser(req.dbCon, req.session.user.id, function(err, userInfo) {
				if(err)
					return next(err);

				params.settings = userInfo;

				async.series([
					function(next) {
						if(req.method == "POST")
						{
							req.session.user = userInfo;
							i18n.middleware(req, res, next);
						}
						else
							next();
					},
					function(next) {
						if(req.method == "POST" && req.body.openid && req.body.openid != userInfo.openid && params.errors.length == 0)
						{
							relyingParty.authenticate(req.body.openid, false, function(err, url) {
								if(url)
									return res.redirect(303, url);

								if(err)
									params.errors.push(req.gettext("OpenID authentication failed: %s", err.message));
								else
									params.errors.push(req.gettext("OpenID authentication failed."));
								next();
							})
						}
						else
							next();

					}
				], next);
			});
		}
	], function(err) {
		if(err)
			return next(err);

		res.soy("settings", params);
	});
};