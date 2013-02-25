var mails = require("../mails");
var config = require("../config");
var keys = require("../keys");

exports.post = exports.get = function(req, res, next, isPost) {

	// Not logged in: can’t claim key, redirect to login page
	if(!req.session.user)
		return res.redirect(303, config.baseurl + "/login?referer=" + encodeURIComponent(req.url));

	keys.getKeySettings(req.dbCon, req.params.keyId, function(err, settings) {
		if(err)
			return next(err);

		if(settings && settings.user)
		{
			// Key has user assigned: if current user, display success message, else redirect to key
			if(req.session.user && settings.user == req.session.user.id)
			{
				req.params.verified = true;
				next();
			}
			else
				req.redirect(303, config.baseurl + "/key/" + encodeURIComponent(req.params.keyId));
		}
		else if(req.method == "POST")
		{
			// POST: Send verification e-mail
			req.params.sent = true;
			mails.sendVerificationMail(req.params.keyId, req.session.user, next);
		}
		else if(req.query.token)
		{
			// Token is set: set key ownership if token is correct
			mails.verifyVerificationMail(req.params.keyId, req.session.user, req.query.token, function(err, verified) {
				if(err)
					return next(err);

				req.params.verified = verified;
				next();
			})
		}
		else
			next();
	});
};