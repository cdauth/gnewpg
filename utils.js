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

/**
 * Buffers the output of a readable stream and makes it readable in a predictable manner.
 * 
 * This function returns a method of the type function(bytes, callback). The callback function is called as soon as
 * the specified number of bytes is available, receiving a possible error message as first argument or a Buffer object
 * with the exact specified amount of bytes as second argument. If the bytes parameter is set to -1, the callback
 * function will only be called when the readable stream has reached its end, then passing the full content to the function.
 * 
 * If the stream ends before the requested number of bytes is available, the callback function will be called with an error
 * message.
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
				wantToRead[i].callback(null, buffer);
				buffer = new Buffer(0);
			}
			else if(wantToRead[i].bytes != -1 && buffer.length >= wantToRead[i].bytes)
			{
				wantToRead[i].callback(null, buffer.slice(0, wantToRead[i].bytes));
				buffer = buffer.slice(wantToRead[i].bytes);
			}
			else if(ended)
				callback(new Error("Stream has ended before the requested number of bytes was sent."));
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