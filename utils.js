var config = require("./config");
var fs = require("fs");
var pgp = require("node-pgp");

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

function encodePassword(password) {
	return pgp.utils.hash(password, "sha256", "base64").substring(0, 43);
}

exports.generateRandomString = generateRandomString;
exports.extend = extend;
exports.encodePassword = encodePassword;