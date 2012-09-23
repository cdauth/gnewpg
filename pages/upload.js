var keysUpload = require("../keysUpload");
var fs = require("fs");

module.exports.post = function(req, res, next) {
	var f = req.files.file;
	if(!f)
		f = [ ];
	else if(!Array.isArray(f))
		f = [ f ];
	
	var uploadedKeys = [ ];
	var errors = [ ];
	var failed = [ ];
	
	handleNext(0);
	function handleNext(i) {
		if(i == f.length)
		{
			end();
			return;
		}
		
		keysUpload.uploadKey(fs.createReadStream(f[i].path), function(err, uploaded) {
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
			
			fs.unlink(f[i].path, function(err) {
				if(err)
				{
					console.warn("Error removing uploaded key file", err);
					errors.push(err);
				}
				handleNext(++i);
			});
		}, req.session.user ? req.session.user.id : null);
	}
	
	function end() {
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
			
			next();
		}, req.session.user ? req.session.user.id : null);
	}
}