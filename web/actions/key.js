var keys = require("../../keys");
var pgp = require("node-pgp");
var async = require("async");
var keyrings = require("../../keyrings");
var utils = require("../../utils");
var config = require("../../config");
var users = require("../../users");
var mails = require("../../mails");

var ATTR_MAX_WIDTH = 350;
var ATTR_MAX_HEIGHT = 250;

module.exports = function(app) {
	app.get("/key/:keyId", _showKeyPage);
	app.get("/key/:keyId/settings", _keySettings);
	app.post("/key/:keyId/settings", _keySettings);
	app.get("/key/:keyId/export", function(req, res, next) {
		if(req.query.addKey || req.query.removeKey) {
			utils.checkReferrer(req, res, function(err) {
				if(err)
					return next(err);

				req.body.addKey = req.query.addKey;
				req.body.removeKey = req.query.removeKey;
				_addRemoveKeys(req, res, next);
			});
		}
		else
			_exportKey(req, res, next);
	});
	app.get("/key/:keyId/claim", _claimKey);
	app.post("/key/:keyId/claim", _claimKey);
};

function _showKeyPage(req, res, next) {
	var keyId = req.params.keyId;
	var details = req.query.details;
	var params = { keyId: keyId, details: details, pictures: [ ]}

	keys.getKeyWithSubobjects(req.keyring, keyId, details, function(err, keyDetails) {
		if(err)
			return next(err);
		else if(keyDetails == null)
			return res.soy("key", params);

		keys.getKeySettings(req.dbCon, keyId, function(err, keySettings) {
			if(err)
				return next(err);

			params.keySettings = keySettings;
			params.keyDetails = keyDetails;

			async.waterfall([
				function(next) {
					req.keyring._containsKey(keyId, next);
				},
				function(inKeyring, next) {
					keyDetails.inKeyring = inKeyring;

					if(keyDetails == null)
						return next();

					var pictureIdx = 1;
					async.forEachSeries(keyDetails.attributes, function(attributeInfo, next) {
						var thisPictures = [ ];
						async.forEachSeries(attributeInfo.subPackets, function(subPacket, next) {
							if(subPacket.type != pgp.consts.ATTRSUBPKT.IMAGE || subPacket.imageType != pgp.consts.IMAGETYPE.JPEG)
								return next();

							utils.scaleImage(subPacket.image, ATTR_MAX_WIDTH, ATTR_MAX_HEIGHT, function(err, scaleImg, width, height) {
								if(err)
									return next(err);

								thisPictures.push(pictureIdx);
								params.pictures.push({ idx: pictureIdx, src: "data:image/jpeg;base64,"+scaleImg.toString("base64"), width: width, height: height, attr: attributeInfo });
								pictureIdx++;
								next();
							})
						}, function(err) {
							if(err)
								return next(err);

							if(thisPictures.length > 0)
								attributeInfo.pictures = "#"+thisPictures.join(", #");

							next();
						});
					}, next);
				},
				function(next) {
					if(err || details)
						next(false);
					else
						new keyrings.SearchEngineKeyring(req.dbCon).keyExists(keyId, next);
				}
			], function(err, searchEngines) {
				if(err)
				{
					params.error = err;
					params.searchengines = false;
				}
				else
					params.searchengines = searchEngines;

				res.soy("key", params);
			});
		});
	});
}

function _keySettings(req, res, next) {
	// Not logged in: cannot edit settings
	if(!req.session.user)
		return res.redirectLogin();

	var params = { keyId: req.params.keyId };

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
				params.keySettings = settings;
				params.identities = [ ];
				params.attributes = [ ];

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
								params.identities.push(identitySettings);
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

										params.attributes.push(attributeSettings);
										next();
									});
								});
							}
						], next);
					}, next);
				});
			}
		], function(err) {
			if(err)
				return next(err);

			res.soy("keySettings", params);
		});
	});
}

function _claimKey(req, res, next) {
	// Not logged in: can’t claim key, redirect to login page
	if(!req.session.user)
		return res.redirectLogin();

	var params = { keyId: req.params.keyId };

	function render() {
		res.soy("claimkey", params);
	}

	keys.getKeySettings(req.dbCon, req.params.keyId, function(err, settings) {
		if(err)
			return next(err);

		if(settings && settings.user)
		{
			// Key has user assigned: if current user, display success message, else redirect to key
			if(req.session.user && settings.user == req.session.user.id)
			{
				params.verified = true;
				render();
			}
			else
				req.redirect(303, config.baseurl + "/key/" + encodeURIComponent(req.params.keyId));
		}
		else if(req.method == "POST")
		{
			// POST: Send verification e-mail
			params.sent = true;
			mails.sendVerificationMail(req.params.keyId, req.session.user, function(err) {
				if(err)
					return next(err);

				render();
			});
		}
		else if(req.query.token)
		{
			// Token is set: set key ownership if token is correct
			mails.verifyVerificationMail(req.params.keyId, req.session.user, req.query.token, function(err, verified) {
				if(err)
					return next(err);

				params.verified = verified;
				render();
			})
		}
		else
			render();
	});
}

function _exportKey(req, res, next) {
	exportKeys(req.keyring, req.params.keyId, null, req, res, next);
}

function exportKeys(keyring, keys, filename, req, res, next) {
	if(!Array.isArray(keys))
		keys = [ keys ];

	var formatInfo = utils.getInfoForFormat(req.query.exportFormat);
	if(filename)
		res.attachment(filename+formatInfo.extension);
	else if(keys.length == 1)
		res.attachment("0x"+keys[0]+formatInfo.extension);
	else
		res.attachment("keys"+formatInfo.extension);
	res.type(formatInfo.mimetype);

	var selection = null;

	if(req.query.selection)
	{
		selection = {
			subkeys : { },
			identities : { },
			attributes : { },
			signatures : { }
		};

		for(var i in selection)
		{
			if(!req.query[i])
				continue;
			else if(!Array.isArray(req.query[i]))
				selection[i][req.query[i]] = true;
			else
			{
				req.query[i].forEach(function(it) {
					selection[i][it] = true;
				});
			}
		}
	}

	var streams = [ ];
	for(var i=0; i<keys.length; i++)
		streams.push(keyring.exportKey(keys[i], selection));

	utils.encodeToFormat(pgp.BufferedStream.prototype.concat.apply(streams.shift(), streams), req.query.exportFormat).whilst(function(data, cb) {
		res.write(data, "binary");
		cb();
	}, function(err) {
		if(err)
			next(err);
		else
			res.end();
	});
}

function _addRemoveKeys(req, res, next) {
	if(req.body.removeKey) {
		req.keyring.removeFromKeyring(req.params.keyId, function(err) {
			if(err)
				return next(err);

			res.redirect(303, config.baseurl+"/key/"+encodeURIComponent(req.params.keyId));
		});
	} else {
		req.keyring.addToKeyring(req.params.keyId, function(err) {
			if(err)
				return next(err);

			res.redirect(303, config.baseurl+"/key/"+encodeURIComponent(req.params.keyId));
		});
	}
}

module.exports.exportKeys = exportKeys;