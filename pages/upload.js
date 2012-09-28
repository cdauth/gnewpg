var keys = require("../keys");
var keysUpload = require("../keysUpload");
var fs = require("fs");
var keyrings = require("../keyrings");
var async = require("async");
var utils = require("../utils");
var pgp = require("node-pgp");

module.exports.post = function(req, res, next) {
	var f = req.files.file;
	if(!f)
		f = [ ];
	else if(!Array.isArray(f))
		f = [ f ];
	
	var uploadedKeys = [ ];
	var errors = [ ];
	var failed = [ ];
	
	var keyring = null;
	if(req.session.user)
		keyring = keyrings.getKeyringForUser(req.session.user.id);
	
	async.series([
		function(cb) {
			async.forEachSeries(f, function(it, cb2) {
				keysUpload.uploadKey(fs.createReadStream(it.path), function(err, uploaded) {
					if(err)
					{
						console.warn("Error while uploading key", err);
						errors.push(err);
					}
					else
					{
						uploadedKeys = uploadedKeys.concat(uploaded.uploadedKeys);
						failed = failed.concat(uploaded.failed);
					}
					
					fs.unlink(it.path, function(err) {
						if(err)
						{
							console.warn("Error removing uploaded key file", err);
							errors.push(err);
						}
						cb2();
					});
				}, keyring);
			}, cb);
		},
		function(cb) {
			keysUpload.uploadKey(req.body.paste || "", function(err, uploaded) {
				if(err)
				{
					console.warn("Error while uploading key", err);
					errors.push(err);
				}
				else
				{
					uploadedKeys = uploadedKeys.concat(uploaded.uploadedKeys);
					failed = failed.concat(uploaded.failed);
				}
				
				req.params.uploadedKeys = uploadedKeys;
				req.params.failed = failed;
				req.params.errors = errors;
				
				cb();
			}, keyring);
		}
	], function(err) {
		if(err) { next(err); return; }
		
		if(req.body.downloadupdated)
		{
			var formatInfo = utils.getInfoForFormat(req.body.exportFormat);
			res.attachment("gnewpgUploadedKeys"+formatInfo.extension);
			res.type(formatInfo.mimetype);
			
			var pseudoKeyring = keyring || keyrings.getPseudoKeyringForUploadedKeys(uploadedKeys);
			
			var all = new pgp.BufferedStream();
			async.forEachSeries(uploadedKeys, function(it, cb) {
				keys.exportKey(it.id, pseudoKeyring).whilst(function(data, cb2) {
					all._sendData(data);
					cb2();
				}, cb);
			}, function(err) {
				all._endData(err);
			});

			utils.encodeToFormat(all, req.body.exportFormat).whilst(function(data, cb) {
				res.write(data, "binary");
				cb();
			}, function(err) {
				if(err)
					next(err);
				else
					res.end();
			});
		}
		else
			next();
	});
}