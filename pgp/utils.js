var config = require("./config");
var fs = require("fs");

function getTempFilename(callback)
{
	var cb = function(err) {
		if(err) { callback(err); return; }
		
		var fname = config.tmpDir+"/"+(new Date()).getTime();
		fs.exists(fname, function(exists) {
			if(exists)
				cb();
			else
				callback(null, fname);
		});
	};

	fs.exists(config.tmpDir, function(exists) {
		if(!exists)
			fs.mkdir(config.tmpDir, 0700, cb);
		else
			cb();
	});
}

exports.getTempFilename = getTempFilename;