var config = require("../config");
var db = require("../db");
var utils = require("../utils");

module.exports.post = function(req, res, next) {
	var errors = [ ];

	if(req.body.username)
		req.body.username = req.body.username.trim();
	if(req.body.email)
		req.body.email = req.body.email.trim() || null;

	if(!req.body.username || req.body.username.length < config.usernameMinLength)
		errors.push(req.ngettext("The username has to be at least %d character long.", "The username has to be at least %d characters long.", config.usernameMinLength, config.usernameMinLength));
	else if(req.body.username.length > config.usernameMaxLength)
		errors.push(req.ngettext("The username may be at most %d character long.", "The username may be at most %d characters long.", config.usernameMaxLength, config.usernameMaxLength));
	
	db.entryExists("users", { id: req.body.username }, function(err, exists) {
		if(err)
			next(err);
		else
		{
			if(exists != null)
				errors.push(req.gettext("This username is already taken."));
			if(!req.body.password || req.body.password.length < config.passwordMinLength)
				errors.push(req.ngettext("The password has to be at least %d character long.", "The password has to be at least %d characters long.", config.passwordMinLength, config.passwordMinLength));
			else if(req.body.password != req.body.password2)
				errors.push(req.gettext("The two passwords do not match."));
		
			if(errors.length == 0)
			{
				db.create("users", { id: req.body.username, password: utils.encodePassword(req.body.password), email: req.body.email }, function(err) {
					if(err)
						next(err);
					else
					{
						req.params.success = true;
						next();
					}
				});
			}
			else
			{
				req.params.errors = errors;
				req.params.username = req.body.username;
				req.params.email = req.body.email;
				next();
			}
		}
	});
};