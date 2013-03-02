var keys = require("../keys");
var pgp = require("node-pgp");
var async = require("async");
var keyrings = require("../keyrings");
var utils = require("../utils");

var ATTR_MAX_WIDTH = 350;
var ATTR_MAX_HEIGHT = 250;

exports.get = function(req, res, next) {
	var keyId = req.params.keyId;
	var details = req.params.details = req.query.details;
	req.params.consts = pgp.consts;
	var pictures = req.params.pictures = [ ];

	keys.getKeyWithSubobjects(req.keyring, req.params.keyId, req.params.details, function(err, keyDetails) {
		if(err)
			return next(err);

		keys.getKeySettings(req.dbCon, req.params.keyId, function(err, keySettings) {
			if(err)
				return next(err);

			req.params.keySettings = keySettings;
			req.params.keyDetails = keyDetails;

			async.waterfall([
				function(next) {
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
								pictures.push({ idx: pictureIdx, src: "data:image/jpeg;base64,"+scaleImg.toString("base64"), width: width, height: height, attr: attributeInfo });
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
					req.params.error = err;
					req.params.searchengines = false;
				}
				else
					req.params.searchengines = searchEngines;

				next();
			});
		});
	});
};