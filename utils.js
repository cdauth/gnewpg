var config = require("./config");
var fs = require("fs");

var RANDOM_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/**
 * Generates a random string of the specified length made of letters and numbers.
 * @param length {Number}
*/
function generateRandomString(length) {
	var ret = "";
	for(var i=0; i<length; i++)
		ret += RANDOM_CHARS.charAt(Math.floor(Math.random()*RANDOM_CHARS.length));
	return ret;
};

function extend(obj1, obj2) {
	for(var i=1; i<arguments.length; i++)
	{
		for(var j in arguments[i])
			obj1[j] = arguments[i][j];
	}
	return obj1;
};

function removeDirRecursively(dir, callback) {
	fs.readdir(dir, function(err, files) {
		if(err)
			callback && callback(err);
		else
		{
			var handleFile = function(i) {
				if(i < files.length)
				{
					var fname = dir+"/"+files[i];
					fs.stat(fname, function(err, stats) {
						if(err)
							callback && callback(err);
						else if(stats.isDirectory())
						{
							removeDirRecursively(fname, function(err) {
								if(err)
									callback && callback(err);
								else
									handleFile(i+1);
							});
						}
						else
						{
							fs.unlink(fname, function(err) {
								if(err)
									callback && callback(err)
								else
									handleFile(i+1);
							});
						}
					});
				}
				else
				{
					fs.rmdir(fname, function(err) {
						callback && callback(err);
					});
				}
			};
		}
	});
};

function makeTempDir(callback) {
	var mkdir = function() {
		var dir = config.tempDir+"/"+generateRandomString(16);
		fs.exists(dir, function(exists) {
			if(exists)
				mkdir();
			else
			{
				fs.mkdir(dir, 0700, function(err) {
					if(err)
						callback(err);
					else
					{
						callback(null, dir, function() {
							removeDirRecursively(dir, function(err) {
								if(err)
									console.log("Error removing temporary directory", err);
							});
						});
					}
				});
			}
		});
	};

	fs.exists(config.tempDir, function(exists) {
		if(exists)
			mkdir();
		else
		{
			fs.mkdir(dir, 0700, function(err) {
				if(err)
					callback(err);
				else
					mkdir();
			});
		}
	});
};

/**
 * Buffers the output of a readable stream and makes it readable in a predictable manner.
 * 
 * This function returns a method of the type function(bytes, callback). The callback function is called as soon as
 * the specified number of bytes is available, receiving a Buffer object (with the exact amount of bytes specified)
 * only argument. If the bytes parameter is set to -1, the callback function will only be called when the readable
 * stream has reached its end, then passing the full content to the function.
 * 
 * As some methods of the PGP implementation take this function as an argument, instead of the stream you can also
 * pass a Buffer object if that is more convenient to you.
 * 
 * @param stream {Readable Stream|Buffer} The stream to read from
*/
function bufferReadableStream(stream) {
	var buffer = (stream instanceof Buffer ? stream : new Buffer(0));
	var wantToRead = [ ];
	var ended = false;
	
	var checkRead = function() {
		var i=0;
		for(; i<wantToRead.length; i++)
		{
			if(wantToRead[i].bytes == -1 && ended)
			{
				wantToRead[i].callback(buffer);
				break;
			}
			else if(wantToRead[i].bytes != -1 && buffer.length >= wantToRead[i].bytes)
			{
				wantToRead[i].callback(buffer.slice(0, wantToRead[i].bytes));
				buffer = buffer.slice(wantToRead[i].bytes);
			}
			else
				break;
		}
		if(i > 0)
			wantToRead = wantToRead.slice(i);
	};
	
	if(!(stream instanceof Buffer))
	{
		stream.on("data", function(data) {
			buffer = Buffer.concat([ buffer, data ]);
			
			checkRead();
		});
		stream.on("end", function(data) {
			ended = true;
			
			checkRead();
		});
	}
	
	return function(bytes, callback) {
		wantToRead.push({ bytes: bytes, callback: callback });
		checkRead();
	};
}

exports.generateRandomString = generateRandomString;
exports.extend = extend;
exports.removeDirRecursively = removeDirRecursively;
exports.makeTempDir = makeTempDir;
exports.bufferReadableStream = bufferReadableStream;