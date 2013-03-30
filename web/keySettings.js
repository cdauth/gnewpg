var config = require("../config");
var keys = require("../keys");
var pgp = require("node-pgp");
var async = require("async");
var users = require("../users");
var utils = require("../utils");

exports.get = exports.post = function(req, res, next) {

	// Not logged in: cannot edit settings
	if(!req.session.user)
		return res.redirect(303, config.baseurl + "/login?referer=" + encodeURIComponent(req.url));

	keys.getKeySettings(req.dbCon, req.params.keyId, function(err, settings) {
		if(err)
			return next(err);

		// Not the owner: Redirect back to key page
		if(settings.user != req.session.user.id)
			return res.redirect(303, config.baseurl + "/key/" + encodeURIComponent(req.params.keyId));

		if(req.body.dropownership)
		{
			keys.updateKeySettings(req.dbCon, req.params.keyId, { user: null }, function(err) {
				if(err)
					return next(err);

				async.series([
					function(next) {
						if(req.session.user.mainkey == req.params.keyId)
							users.updateUser(req.dbCon, req.session.user.id, { mainkey: null }, next);
						else
							next();
					},
					function(next) {
						res.redirect(303, config.baseurl + "/key/" + encodeURIComponent(req.params.keyId));
					}
				], next);
			});
			return;
		}

		async.series([
			function(next) {
				if(req.method == "POST")
				{
					var newSettings = { perm_idsearch: req.body.perm_idsearch != null, perm_searchengines: req.body.perm_searchengines != null};
					pgp.utils.extend(settings, newSettings);
					keys.updateKeySettings(req.dbCon, req.params.keyId, newSettings, next);
				}
				else
					next();
			},
			function(next) {
				req.params.keySettings = settings;
				req.params.identities = [ ];
				req.params.attributes = [ ];

				req.keyring.getIdentityList(req.params.keyId).forEachSeries(function(identityId, next) {
					var hash = pgp.utils.hash(new Buffer(identityId), "sha1", "hex");
					async.series([
						function(next) {
							if(req.method == "POST")
								keys.updateIdentitySettings(req.dbCon, req.params.keyId, identityId, { perm_public: req.body["perm_public-"+hash] != null, perm_namesearch: req.body["perm_namesearch-"+hash] != null, perm_emailsearch: req.body["perm_emailsearch-"+hash] != null }, next);
							else
								next();
						},
						function(next) {
							keys.getIdentitySettings(req.dbCon, req.params.keyId, identityId, function(err, identitySettings) {
								if(err)
									return next(err);

								identitySettings.hash = hash;
								req.params.identities.push(identitySettings);
								next();
							});
						}
					], next);
				}, function(err) {
					if(err)
						return next(err);

					req.keyring.getAttributes(req.params.keyId, null, [ "id", "subPackets" ]).forEachSeries(function(attributeInfo, next) {
						async.series([
							function(next) {
								if(req.method == "POST")
									keys.updateAttributeSettings(req.dbCon, req.params.keyId, attributeInfo.id, { perm_public: req.body["perm_public-"+attributeInfo.id] != null }, next);
								else
									next();
							},
							function(next) {
								keys.getAttributeSettings(req.dbCon, req.params.keyId, attributeInfo.id, function(err, attributeSettings) {
									if(err)
										return next(err);

									attributeSettings.images = [ ];
									async.forEachSeries(attributeInfo.subPackets, function(it, next) {
										if(!it.image)
											return next();

										utils.scaleImage(it.image, null, 25, function(err, resized) {
											if(err)
												console.log("Error resizing image: ", err);
											else
												attributeSettings.images.push("data:image/jpeg;base64,"+(new Buffer(resized, "binary")).toString("base64"));
											next();
										});
									}, function(err) {
										if(err)
											return next(err);

										req.params.attributes.push(attributeSettings);
										next();
									});
								});
							}
						], next);
					}, next);
				});
			}
		], next);
	});
};