var config = require("./config");
var child_process = require("child_process");
var packets = require("./packets")

function verifyBinarySignature(binary, signature, callback) {
	if(!Array.isArray(binary))
		binary = [ binary ];
	
	var signatureHacked = new Buffer(signature.length);
	signature.copy(signatureHacked);
	var version = signatureHacked.readUInt8(0);
	if(version == 3)
		signatureHacked.writeUInt8(0x00, 2);
	else if(version == 4)
		signatureHacked.writeUInt8(0x00, 1);
	else
	{
		callback(new Error("Unknown signature type "+version+"."));
		return;
	}

	var gpg = child_process.exec(config.gpg, [ "--list-packets" ], function(err, stdout, stderr) {
		console.log(err, stdout, stderr, "hallo");
		if(err)
			callback(err);
		else
			callback();
	});

	gpg.stdin.write(packets.generateNewHeader(2, signatureHacked.length));
	gpg.stdin.write(signatureHacked);
	
	binary.forEach(function(it) {
		gpg.stdin.write(packets.generateNewHeader(11, it.length));
		gpg.stdin.write(it);
	});

	gpg.stdin.end();
}

function getSignedPartForKey(keyBody) {
	var data = new Buffer(keyBody.length+3);
	data.writeUInt8(0x99, 0);
	data.writeUInt16BE(keyBody.length, 1);
	keyBody.copy(data, 3);
	return data;
}

function getSignedPartForIdentityV3(keyBody, idBody) {
	return Buffer.concat([ getSignedPartForKey(keyBody), idBody ]);
}

function getSignedPartForAttributeV3(keyBody, attributeBody) {
	return getSignedPartForIdentityV3(keyBody, idBody);
}

function getSignedPartForIdentityV4(keyBody, idBody) {
	var keyData = getSignedPartForKey(keyBody);
	var data = new Buffer(5 + idBody.length);
	data.writeUInt8(0xB4, 0);
	data.writeUInt32BE(idBody.length, 1);
	idBody.copy(data, 5);
	return [ keyData, data ];
}

function getSignedPartForAttributeV4(keyBody, idBody) {
	var data = getSignedPartForIdentityV4(keyBody, idBody);
	data.writeUInt8(0xD1, keyData.length);
	return data;
}


function verifyKeySignature(keyBody, signature, callback) {
	verifyBinarySignature(getSignedPartForKey(keyBody), signature, callback);
}

function verifyIdentitySignature(keyBody, idBody, signature, callback) {
	var gpg = child_process.exec(config.gpg, [ "--check-sigs", "--no-default-keyring", "--keyring", "/dev/stdin" ], function(err, stdout, stderr) {
		console.log(err, stdout, stderr, "asdfsaf");
		if(err)
			callback(err);
		else
			callback();
	});

	gpg.stdin.write(packets.generateNewHeader(6, keyBody.length));
	gpg.stdin.write(keyBody);
	
	gpg.stdin.write(packets.generateNewHeader(13, idBody.length))
	gpg.stdin.write(idBody);
	
	gpg.stdin.write(packets.generateNewHeader(2, signature.length));
	gpg.stdin.write(signature);

	gpg.stdin.end();
}

function verifyAttributeSignature(keyBody, attributeBody, signature, callback) {
	var version = signature.readUInt8(0);
	if(version == 3)
		verifyBinarySignature(getSignedPartForAttributeV3(keyBody, attributeBody), signature, callback);
	else if(version == 4)
		verifyBinarySignature(getSignedPartForAttributeV4(keyBody, attributeBody), signature, callback);
	else
		callback(new Error("Unknown signature version "+version+"."));
}

exports.verifyBinarySignature = verifyBinarySignature;
exports.verifyKeySignature = verifyKeySignature;
exports.verifyIdentitySignature = verifyIdentitySignature;
exports.verifyAttributeSignature = verifyAttributeSignature;