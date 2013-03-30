var keys = require("../keys");
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

	async.series([
		function(cb) {
			async.forEachSeries(f, function(it, cb2) {
				req.keyring.importKeys(fs.createReadStream(it.path), function(err, uploaded) {
					if(err)
					{
						console.warn("Error while uploading key", err);
						errors.push(err);
					}
					else
					{
						uploadedKeys = uploadedKeys.concat(uploaded.keys);
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
				});
			}, cb);
		},
		function(cb) {
			req.keyring.importKeys(req.body.paste || "", function(err, uploaded) {
				if(err)
				{
					console.warn("Error while uploading key", err);
					errors.push(err);
				}
				else
				{
					uploadedKeys = uploadedKeys.concat(uploaded.keys);
					failed = failed.concat(uploaded.failed);
				}
				
				req.params.uploadedKeys = uploadedKeys;
				req.params.failed = failed;
				req.params.errors = errors;
				
				cb();
			});
		}
	], function(err) {
		if(err)
			return end(err);

		for(var i=0; i<req.params.failed.length; i++)
		{
			if(req.params.failed[i].type == pgp.consts.PKT.RING_TRUST)
			{
				req.params.failed = req.params.failed.slice(0, i).concat(req.params.failed.slice(i+1));
				i--;
			}
		}
		
		if(req.body.downloadupdated)
		{
			var formatInfo = utils.getInfoForFormat(req.body.exportFormat);
			res.attachment("gnewpgUploadedKeys"+formatInfo.extension);
			res.type(formatInfo.mimetype);

			var all = new pgp.BufferedStream();
			async.forEachSeries(uploadedKeys, function(it, cb) {
				req.keyring.exportKey(it.id).whilst(function(data, cb2) {
					all._sendData(data);
					cb2();
				}, cb);
			}, function(err) {
				all._endData(err);
			});

			utils.encodeToFormat(all, req.body.exportFormat).whilst(function(data, cb) {
				res.write(data, "binary");
				cb();
			}, end);
		}
		else
			end();
	});

	function end(err) {
		if(err)
		{
			req.keyring.revertChanges(function(err2) {
				next(err);
			});
		}
		else
		{
			req.keyring[req.body.donotpublish ? "revertChanges" : "saveChanges"](function(err2) {
				if(err2 || !req.body.downloadupdated)
					next(err2);
				else
					res.end();
			});
		}
	}
}