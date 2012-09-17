var child_process = import("child_process");
var config = import("./config");
var utils = import("./utils");
var fs = import("fs");

var TAG_PUBLIC_KEY = 6;
var TAG_SIGNATURE = 2;
var TAG_IDENTITY = 13;
var TAG_PUBLIC_SUBKEY = 14;
var TAG_ATTRIBUTE = 17;

var SIG_CERT_0 = 0x10;
var SIG_CERT_1 = 0x11;
var SIG_CERT_2 = 0x12;
var SIG_CERT_3 = 0x13;
var SIG_SUBKEY = 0x18;
var SIG_KEY_BY_SUBKEY = 0x19;
var SIG_KEY = 0x1F;
var SIG_KEY_REVOK = 0x20;
var SIG_SUBKEY_REVOK = 0x28;
var SIG_CERT_REVOK = 0x30;

var SIGSUB_SIG_CREATION = 2;
var SIGSUB_SIG_EXPIRATION = 3;
var SIGSUB_SIG_EXPORTABLE = 4;
var SIGSUB_SIG_TRUST = 5;
var SIGSUB_SIG_TRUST_REGEXP = 6;
var SIGSUB_KEY_EXPIRATION = 9;
var SIGSUB_SIG_ISSUER = 16;
var SIGSUB_ID_PRIMARY = 25;
var SIGSUB_SIG_POLICY = 26;
var SIGSUB_KEY_FLAGS = 27;
var SIGSUB_SIG_KEY = 28;
var SIGSUB_SIG_REVOK_REASON = 29;

// Key flags (specified in self-signature)
var FLAG_CERTIFY = 0x01;
var FLAG_SIGN = 0x02;
var FLAG_ENCRYPT_COMM = 0x04;
var FLAG_ENCRYPT_FILES = 0x08;
var FLAG_AUTH = 0x20;

function decodeKeyFormat(keyBinary, callback) {
	var gpg = child_process.spawn(config.gpg, [ '--dearmor' ]);
	var error = false;

	gpg.on("exit", function(code) {
		if(code !== 0)
		{
			error = true;
			callback(new Error("gpg exited with error code "+code)));
		}
	});
	
	gpg.stdin.write(keyBinary);
	gpg.stdin.end();
	
	storeKeyInfo(gpg.stdout, function(err, affectedKeys) {
	});
}

function getHeaderLength(packet)
{
	var byte = packet.readUInt8(i++);
	if(byte & 0x80 == 0) // 0x80 == 10000000
		return null;
	else if(byte & 0x40)
	{ // New packet format
		
	}
	else
	{ // Old packet format
		switch(byte & 0x03) // 0x03 == 00000011
		{
			case 0:
				return 2;
			case 1:
				return 3;
			case 2:
				return 5;
			case 3:
				return 1;
		}
	}
}

/**
 * Reads a 1, 2 or 5 octet number from an OpenPGP packet as specified in RFC 4880 section 4.2.2
 * 
 * @param read {Function} A function returned by {@link utils.bufferReadableStream}.
 * @param callback {Function} function(error, number, binary) If the number represents a partial body length, it
 *                            is multiplied with -1. The binary parameter is the binary representation of the number.
*/
function read125OctetNumber(read, callback)
{
	read(1, function(err, data1) {
		if(err)
		{
			err.NOFIRSTBYTE = true;
			callback(err);
		}
		else
		{
			binary = data1;
			
			var byte1 = data1.readUInt8(0);
			if(byte1 < 192)
				callback(byte1, binary);
			else if(byte1 < 224)
			{
				read(1, function(data2, err) {
					if(err)
						callback(err);
					else
					{
						binary = Buffer.concat([ binary, data2 ]);
						callback(null, ((byte1 - 192) << 8) + data2.readUInt8(0) + 192, binary);
					}
				});
			}
			else if(byte1 < 255)
				callback(-(1 << (byte1 & 0x1F)));
			else if(byte1 == 255)
			{
				read(4, function(err, data2) {
					if(err)
						callback(err);
					else
					{
						binary = Buffer.concat([ binary, data2 ]);
						callback(null, data2.readUInt32BE(0), binary);
					}
				});
			}
		}
	};
}

function encode125OctetNumber(number, partial)
{
	if(number < 192)
	{
		var ret = new Buffer(1)
		ret.writeUInt8(number, 0);
		return ret;
	}
	else if(number < 8384)
	{
		var ret = new Buffer(2);
		ret.writeUInt8(((number-192) >> 8) + 192, 0);
		ret.writeUInt8((number-192) & 0xFF, 1);
		return ret;
	}
	else
	{
		var ret = new Buffer(5);
		ret.writeUInt8(255, 0);
		ret.writeUInt32(number, 1);
		return ret;
	}
}

/**
 * Extracts the information of an OpenPGP packet header.
 * 
 * @param read {Function} A function returned by {@link utils.bufferReadableStream}.
 * @param callback {Function} function(error, tag, packetLength, header), where tag is the packet type, packetLength
 *                            is the length of the packet and header is the binary data of the header. If packetLength
 *                            is null, the packet goes until EOF. If packetLength is negative, this is a partial body
 *                            length (RFC 4880 Section 4.2.2.4), and the number multiplied with -1 will be the length
 *                            of the first part.
*/
function getHeaderInfo(read, callback)
{
	read(1, function(err, data1) {
		if(err)
		{
			err.NOFIRSTBYTE = true;
			callback(err);
		}
		else
		{
			var header = data1;

			var byte1 = data1.readUInt8(0);
			if(byte1 & 0x80 == 0) // 0x80 == 10000000
				callback(new Error("This is not an OpenPGP packet."));
			else if(byte1 & 0x40)
			{ // New packet format
				var tag = (byte1 & 0x3F); // 0x3F == 00111111

				read125OctetNumber(read, function(err, number, binary) {
					if(err)
						callback(err);
					else
					{
						header = Buffer.concat([ header, binary ]);
						callback(null, tag, number, header);
					}
				});
			}
			else
			{
				var tag = (byte1 >> 2) & 0x0F; // 0x0F == 00001111
				var headerLength;
				switch(byte1 & 0x03) { // 0x03 == 00000011
					case 0: headerLength = 2; break;
					case 1: headerLength = 3; break;
					case 2: headerLength = 5; break;
					case 3: headerLength = 1; break;
				}
				if(headerLength == 1) // Packet length until EOF
					callback(null, tag, null, header);
				else
				{
					read(headerLength-1, function(err, data2) {
						if(err)
							callback(err)
						else
						{
							header = Buffer.concat([ header, data2 ]);

							var packetLength;
							switch(headerLength) {
								case 2: packetLength = data2.readUInt8(); break;
								case 3: packetLength = data2.readUInt16BE(); break;
								case 4: packetLength = data2.readUInt32BE(); break;
							}
							callback(null, tag, packetLength, header);
						}
					});
				}
			}
		}
	});
}

function generateHeader(tag, packetLength)
{
	var number = encode125OctetNumber(packetLength);
	var ret = Buffer.concat([ new Buffer(1), number ]);
	ret.writeUInt8(0xc0 | tag, 0); // 0xc0 == 11000000
	return ret;
}

/**
 * Splits an OpenPGP message into its packets. If any of the packets contains partial body length headers, it will be converted to a package with a fixed length.
 * 
 * @param keyBinaryStream {Function} A function as returned by utils.bufferReadableStream
 * @param callback {Function} function(error, tag, header, body, next), where tag is the packet type, header the binary
 *                            data of the header and body the binary body data. The callback function will be called
 *                            once for each packet. It will only proceed to the next package when the next() function is called.
 *                            This is important, as the order of the packets is important and one should be able to use asynchronous
 *                            code in the callback function.
 * @param callbackEnd {Function} THis function is called when the callback function for the last packet calls next()
*/
function gpgsplit(keyBinaryStream, callback, callbackEnd) {
	var readPacket = function() {
		getHeaderInfo(keyBinaryStream, function(err, tag, packetLength, header) {
			if(err)
			{
				if(!err.NOFIRSTBYTE) // If NOFIRSTBYTE is true, we have reached the end of the stream
					callback(err);
			}
			else
			{
				if(packetLength < 0) // Partial body length
				{
					keyBinaryStream(-packetLength, function(err, body) {
						var readon = function() {
							read125OctetNumber(keyBinaryStream, function(err, length) {
								if(err)
									callback(err);
								else
								{
									keyBinaryStream(Math.abs(length), function(err, part) {
										if(err)
											callback(err);
										else
										{
											body = Buffer.concat(body, part);
											if(length < 0)
												readon();
											else
											{
												header = generateHeader(tag, body.length);
												callback(null, tag, header, body, readPacket);
											}
										}
									});
								}
							});
						};
						readon();
					});
				}
				else
				{
					keyBinaryStream(packetLength === null ? -1 : packetLength, function(err, body) {
						if(err)
							callback(err);
						else
							callback(null, tag, header, body, readPacket);
					});
				}
			}
		});
	};

	readPacket();
}

function getKeyInfo(binaryStream, callback) {
	var keys = { };
	var lastKey = null;
	var lastSubobject = null; // Subkey, identity or attribute
	var lastSubobjectType = null;

	var errors = false;

	gpgsplit(binaryStream, function(err, tag, header, body, next) {
		if(err) { callback(err); return; }
		
		switch(tag)
		{
			case TAG_PUBLIC_KEY:
				lastKey = lastSubobject = null;
				extractKeyInfo(body, function(err, info) {
					if(err) { errors = true; return }

					if(!keys[info.id])
						keys[info.id] = info;
					lastkey = keys[info.id];

					next();
				});
				break;
			case TAG_PUBLIC_SUBKEY:
				lastSubobject = null;
				if(lastKey == null)
					errors = true;
				else
				{
					extractSubkeyInfo(body, function(err, info) {
						if(err) { errors = true; return; }
					
						if(!lastKey.subkeys[info.id])
							lastKey.subkeys[info.id] = info;
						lastSubobject = lastKey.subkeys[info.id];
						lastSUbobjectType = "subkey";
						
						next();
					});
				}
				break;
			case TAG_IDENTITY:
				lastSubobject = null;
				if(lastKey == null)
					errors = true;
				else
				{
					extractIdentityInfo(body, function(err, info) {
						if(err) { errors = true; return; }
					
						if(!lastKey.identities[info.id])
							lastKey.identities[info.id] = info;
						lastSubobject = lastKey.identities[info.id];
						lastSubobjectType = "identity";
						
						next();
					});
				}
				break;
			case TAG_ATTRIBUTE:
				lastSubobject = null;
				if(lastKey == null)
					errors = true;
				else
				{
					extractAttributeInfo(body, function(err, info) {
						if(err) { errors = true; return; }
					
						if(!lastKey.attributes[info.id])
							lastKey.attributes[info.id] = info;
						lastSubobject = lastKey.attributes[info.id];
						lastSubobjectType = "attribute";
						
						next();
					});
				}
				break;
			case TAG_SIGNATURE:
				var obj = lastSubobject || lastKey;
				if(obj == null)
					errors = true;
				else
				{
					extractSignatureInfo(body, function(err, info) {
						if(err
							|| (lastSubobject == null && [ SIG_KEY, SIG_KEY_BY_SUBKEY, SIG_KEY_REVOK ].indexOf(info.type) == -1)
							|| (lastSubobjectType == "subkey" && [ SIG_SUBKEY, SIG_SUBKEY_REVOK ].indexOf(info.type) == -1)
							|| ([ "identity", "attribute" ].indexOf(lastSubobjectType) != -1 && [ SIG_CERT_1, SIG_CERT_2, SIG_CERT_3, SIG_CERT_REVOK ].indexOf(info.type == -1)))
						{ // Error on unmatching signature type
							errors = true;
							return;
						}

						if(!obj.signatures[info.id])
							obj.signatures[info.id] = info;
						
						next();
					});
				}
				break;
	}, function() {
		// All packets have beend handled
		callback(null, keys, errors);
	});
}

function extractKeyInfo(data, callback)
{
	listPackets(data, function(err, info) {
		if(err)
			callback(err);
		else
		{
			var key = {
				id: null,
				subkeys: { },
				attributes: { },
				signatures: { },
				identities: { },
				binary : data
			};
			var m = info.match(/^\s*keyid: (.*)\s*$/m);
			if(m)
				key.id = m[1];

			callback(null, key);
		}
	});
}

function extractIdentityInfo(data, callback)
{
	callback(null, data.substring(2));
}

function extractSubkeyInfo(data, callback)
{
	extractPublicKeyInfo(data, callback);
}

function extractAttributeInfo(data, callback)
{
}

function extractSignatureInfo(data, callback)
{
	var byte1 = data.readUInt8(0);
	if(byte1 == 3)
	{ // Version 3 signature
		if(data.readUInt8(1) != 5)
			callback(new Error("Invalid signature data."));
		else
		{
			callback(null, {
				type : data.readUInt8(2),
				date : new Date(data.readUInt32BE(3)),
				bykey : data.toString("hex", 7, 15);
				pkalgo : data.readUInt8(16),
				hashalgo : data.readUInt8(17)
				version : 3,
				binary : data,
				verified : false
			});
		}
	}
	else if(byte1 == 4)
	{ // Version 4 signature
		var ret = {
			type : data.readUInt8(1),
			date : null,
			pkalgo : data.readUInt8(2),
			hashalgo : data.readUInt8(3),
			version : 4,
			binary : data,
			verified : false
		};
		
		extractSignatureSubPackets(data, function(err, info) {
			if(err) { callback(err); return; }
			
			callback(null, utils.extend(ret, info));
		});
	}
	else
		callback(new Error("Unknown signature version "+byte1+"."));
}

function extractSignatureSubPackets(data, callback)
{
	var sublength = data.readUInt16BE(4);
	var read = utils.bufferReadableStream(data.slice(4, sublength-4));
	
	var info = {
		date: null,
		expiration: null,
		exportable: true,
		trustlevel: null,
		trustamount: null,
		trustregexp: null,
		bykey: null,
		keyExpiration: null,
		primaryId: null,
		policy: null,
		flags: null,
		revokationReasonType: null,
		revokationReasonExplanation: null
	};
	
	var readon = function() {
		read125OctetNumber(read, function(err, number) {
			if(err) { callback(err); return; }
			
			read(number, function(err, data2) {
				if(err)
				{
					if(err.NOFIRSTBYTE)
						callback(info);
					else
						callback(err);
					return;
				}
				
				var type = data2.readUInt8(0);
				var critical = !!(type | 0x80);
				type = type & 0x7F;
				
				switch(type) {
					case SIGSUB_SIG_CREATION:
						info.date = new Date(data2.readUInt32BE(1)*1000);
						break;
					case SIGSUB_SIG_EXPIRATION:
						info.expiration = data2.readUInt16BE(1);
						break;
					case SIGSUB_SIG_EXPORTABLE:
						info.exportable = !!data2.readUInt8(1);
						break;
					case SIGSUB_SIG_TRUST:
						var trustlevel = data2.readUInt8(1);
						if(trustlevel > 0)
						{
							info.trustlevel = trustlevel;
							info.trustamount = data2.readUInt8(2);
						}
						break;
					case SIGSUB_SIG_TRUSTREGEXP:
						var regexp = data2.toString("utf8", 1, data2.length);
						var idx = regexp.indexOf("\0");
						info.trustregexp = (idx == -1 ? regexp : regexp.substr(0, idx));
						break;
					case SIGSUB_KEY_EXPIRATION:
						info.keyExpiration = data2.readUInt16BE(1);
						break;
					case SIGSUB_SIG_ISSUER:
						info.bykey = data2.toString("hex", 1, 9);
						break;
					case SIGSUB_ID_PRIMARY:
						info.primaryId = !!data2.readUInt8(1);
						break;
					case SIGSUB_SIG_POLICY:
						info.policy = data2.toString("utf8", 1);
						break;
					case SIGSUB_KEY_FLAGS:
						info.flags = data2.readUInt8(1);
						break;
					case SIGSUB_SIG_REVOK_REASON:
						info.revokationReasonType = data2.readUInt8(1);
						info.revokationReasonExplanation = data2.toString("utf8", 2);
						break;
					default:
						if(critical)
						{
							callback(new Error("Unimplemented critical signature subpacket type "+type+"."));
							return;
						}
				}
				
				readon();
			});
		})
	};
}

var SIGSUB_SIG_CREATION = 2;
var SIGSUB_SIG_EXPIRATION = 3;
var SIGSUB_SIG_EXPORTABLE = 4;
var SIGSUB_SIG_TRUST = 5;
var SIGSUB_SIG_TRUST_REGEXP = 6;
var SIGSUB_KEY_EXPIRATION = 9;
var SIGSUB_SIG_ISSUER = 16;
var SIGSUB_ID_PRIMARY = 25;
var SIGSUB_SIG_POLICY = 26;
var SIGSUB_KEY_FLAGS = 27;
var SIGSUB_SIG_REVOK_REASON = 29;