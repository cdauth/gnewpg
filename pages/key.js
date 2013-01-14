var keys = require("../keys");
var pgp = require("node-pgp");
var pgpPg = require("node-pgp-postgres");
var async = require("async");
var keyrings = require("../keyrings");

exports.get = function(req, res, next) {
	var keyId = req.params.keyId;
	var details = req.params.details = req.query.details;
	req.params.consts = pgp.consts;
	var pictures = req.params.pictures = [ ];

	keys.getKeyWithSubobjects(req.keyring, req.params.keyId, req.params.details, function(err, keyDetails) {
		if(err)
			return end(err);

		req.params.keyDetails = keyDetails;

		var pictureIdx = 1;
		keyDetails.attributes.forEach(function(attributeInfo) {
			var thisPictures = [ ];
			attributeInfo.subPackets.forEach(function(subPacket) {
				if(subPacket.type == pgp.consts.ATTRSUBPKT.IMAGE && subPacket.imageType == pgp.consts.IMAGETYPE.JPEG)
				{
					subPacket.pictureIdx = pictureIdx;
					thisPictures.push(pictureIdx);
					pictures.push({ idx: pictureIdx, src: "data:image/jpeg;base64,"+subPacket.image.toString("base64"), attr: attributeInfo });
					pictureIdx++;
				}
			});

			if(thisPictures.length > 0)
				attributeInfo.pictures = "#"+thisPictures.join(", #");
		});

		end();
	});

	function end(err) {
		if(err)
			req.params.error = err;

		async.waterfall([
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
	}
};