var keys = require("../../keys");
var fs = require("fs");
var keyrings = require("../../keyrings");
var async = require("async");
var utils = require("../../utils");
var pgp = require("node-pgp");

module.exports = function(app) {
	app.get("/upload", _showUploadForm);
	app.post("/upload", _doUpload);
};

function _showUploadForm(req, res, next) {
	res.soy("upload");
}

function _doUpload(req, res, next) {
	var f = req.files.file;
	if(!f)
		f = [ ];
	else if(!Array.isArray(f))
		f = [ f ];

	var params = {
		uploadedKeys : [ ],
		errors : [ ],
		failed : [ ]
	};

	async.series([
		function(cb) {
			// Import uploaded files
			async.forEachSeries(f, function(it, cb2) {
				req.keyring.importKeys(fs.createReadStream(it.path), function(err, uploaded) {
					if(err)
					{
						console.warn("Error while uploading key", err);
						params.errors.push(err);
					}
					else
					{
						params.uploadedKeys = params.uploadedKeys.concat(uploaded.keys);
						params.failed = params.failed.concat(uploaded.failed);
					}
					
					fs.unlink(it.path, function(err) {
						if(err)
						{
							console.warn("Error removing uploaded key file", err);
							params.errors.push(err);
						}
						cb2();
					});
				});
			}, cb);
		},
		function(cb) {
			// Import pasted keys
			req.keyring.importKeys(req.body.paste || "", function(err, uploaded) {
				if(err)
				{
					console.warn("Error while uploading key", err);
					params.errors.push(err);
				}
				else
				{
					params.uploadedKeys = params.uploadedKeys.concat(uploaded.keys);
					params.failed = params.failed.concat(uploaded.failed);
				}
				
				cb();
			});
		}
	], function(err) {
		if(err)
			return end(err);

		for(var i=0; i<params.failed.length; i++)
		{
			if(params.failed[i].type == pgp.consts.PKT.RING_TRUST)
			{
				params.failed = params.failed.slice(0, i).concat(params.failed.slice(i+1));
				i--;
			}
		}
		
		if(req.body.downloadupdated)
		{
			var formatInfo = utils.getInfoForFormat(req.body.exportFormat);
			res.attachment("gnewpgUploadedKeys"+formatInfo.extension);
			res.type(formatInfo.mimetype);

			var all = new pgp.BufferedStream();
			async.forEachSeries(params.uploadedKeys, function(it, cb) {
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
				if(err2)
					next(err2);
				else if(!req.body.downloadupdated)
					res.soy("upload", params);
				else
					res.end();
			});
		}
	}
}