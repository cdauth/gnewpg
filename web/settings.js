var users = require("../users");
var config = require("../config");
var utils = require("../utils");
var async = require("async");
var i18n = require("../i18n");
var openid = require("openid");
var keys = require("../keys");

var relyingParty = new openid.RelyingParty(config.baseurl+"/settings?openid_verify=1");

exports.get = exports.post = function(req, res, next) {
	// Not logged in: cannot edit settings
	if(!req.session.user)
		return res.redirect(303, config.baseurl + "/login?referer=" + encodeURIComponent(req.url));

	var errors = req.params.errors = [ ];
	var update = { };
	async.series([
		function(next) {
			keys.resolveKeyList(req.keyring, keys.getKeysOfUser(req.dbCon, req.session.user.id)).toArraySingle(function(err, ownKeys) {
				if(err)
					return next(err);

				req.params.ownKeys = ownKeys;
				next();
			});
		},
		function(next) {
			if(req.method == "POST")
			{
				if((req.body.password && req.body.password.length > 0) || (req.body.password2 && req.body.password2.length > 0))
				{
					if(!req.body.password || req.body.password.length < config.passwordMinLength)
						errors.push(req.ngettext("The password has to be at least %d character long.", "The password has to be at least %d characters long.", config.passwordMinLength, config.passwordMinLength));
					else if(req.body.password != req.body.password2)
						errors.push(req.gettext("The two passwords do not match."));
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
						errors.push(req.gettext("Error verifying openid: %s", err.message));
					else if(!res.authenticated || res.claimedIdentifier != req.session.user.newOpenid)
						errors.push(req.gettext("Error verifying openid."));
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
							errors.push(req.gettext("This OpenID is used by another account already."));
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
				req.params.updated = true;
				users.updateUser(req.dbCon, req.session.user.id, update, next);
			}
			else
				next();
		},
		function(next) {
			users.getUser(req.dbCon, req.session.user.id, function(err, userInfo) {
				if(err)
					return next(err);

				req.params.settings = userInfo;

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
						if(req.method == "POST" && req.body.openid && req.body.openid != userInfo.openid && errors.length == 0)
						{
							relyingParty.authenticate(req.body.openid, false, function(err, url) {
								if(url)
									return res.redirect(303, url);

								if(err)
									req.params.errors.push(req.gettext("OpenID authentication failed: %s", err.message));
								else
									req.params.errors.push(req.gettext("OpenID authentication failed."));
								next();
							})
						}
						else
							next();

					}
				], next);
			});
		}
	], next);
};