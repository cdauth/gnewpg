var keys = require("../keys");
var keysUpload = require("../keysUpload");
var fs = require("fs");
var keyrings = require("../keyrings");
var async = require("async");

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
			async.forEach(f, function(it, cb2) {
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
			res.attachment("gnewpgUploadedKeys.pgp");
			res.type("application/pgp-keys");
			
			var pseudoKeyring = keyring || keyrings.getPseudoKeyringForUploadedKeys(uploadedKeys);
			
			async.forEach(uploadedKeys, function(it, cb) {
				keys.exportKey(it.id, pseudoKeyring).whilst(function(data, cb) {
					res.send(data, "binary");
				}, cb);
			}, function(err) {
				if(err)
					next(err);
			});
		}
		else
			next();
	});
}