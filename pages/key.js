var keys = require("../keys");
var keyrings = require("../keyrings");
var pgp = require("node-pgp");
var async = require("async");

exports.get = function(req, res, next) {
	var keyring = null;
	if(req.session.user)
		keyring = keyrings.getKeyringForUser(req.session.user.id);
	
	req.params.details = !!req.query.details;
	req.params.consts = pgp.consts;

	async.waterfall([
		function(cb) {
			keys.getKeyWithSubobjects(req.params.keyId, keyring, req.params.details, cb);
		},
		function(keyDetails, cb) {
			req.params.keyDetails = keyDetails;
			req.params.pictures = [ ];
			var pictureIdx = 1;
			
			async.forEach(keyDetails.attributes, function(attrRecord, cb2) {
				async.waterfall([
					function(cb3) {
						if(attrRecord.info)
							cb3(null, attrRecord.info);
						else
							pgp.packetContent.getAttributePacketInfo(attrRecord.binary, cb3);
					},
					function(attrInfo, cb3) {
						attrRecord.info = attrInfo;
						var pictures = [ ];

						attrRecord.info.subPackets.forEach(function(subPacket) {
							if(subPacket.type == pgp.consts.ATTRSUBPKT.IMAGE && subPacket.imageType == pgp.consts.IMAGETYPE.JPEG)
							{
								subPacket.pictureIdx = pictureIdx;
								pictures.push(pictureIdx);
								req.params.pictures.push({ idx: pictureIdx, src: "data:image/jpeg;base64,"+subPacket.image.toString("base64"), attr: attrRecord });
								pictureIdx++;
							}
						});
						
						if(pictures.length > 0)
							attrRecord.pictures = "#"+pictures.join(", #");
						
						cb3();
					}
				], cb2);
			}, cb);
		}
	], function(err) {
		if(err)
			req.params.error = err;
		
		req.params.searchengines = (!req.params.error && !req.params.details && req.params.keyDetails.perm_searchengines);
		next();
	});
};