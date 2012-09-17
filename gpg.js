var child_process = import("child_process");
var config = import("./config");
var utils = import("./utils");
var fs = import("fs");

var SAMPLE_KEY = "\x99\x01\xa2\x04PW7\x9c\x11\x04\x00\x93\:\xb9\xdf\x110A\xc9\x89\xcc\x88\x84_\xd0\xd3\x14\xec9\xa7\xaf  ;6\xbd\
[J\x9c\xeb{\x80\xf9qy\xd4\x8f\xc6\x06\xa8\xfe\x10\x97g\"\x11J\xbd\xb9&r\x0b\xdc\x7f4\x98\x85\xff\x8e\x86N\xf9\xc0F\xb0\xb0\xb9]B\
R\x9c\xb4\xd4\x10\x18'(\xa1Q\x0a\xa1\xc2fM=\xc7ds\xd4R\xf2\xcft\xf1\xbdt\xc6s\xd4\xb5.p2\xaej6!I\x14\xcf\xcc\xa4m?\x9eaO\xc1N\x91\
\xfb\x1d\xca\xcf\xd2c|\x1f\x00\xa0\xcf\x19\xab\x82\x0ar\x85\xa91\x0cq\xdb|\xb8\x0c\x00\xd64\xa9\x97\x04\x00\x84M&9\xf8\xa4\x008\"d\
\xf3<x-\xeb\xbd\x89\x12_\xd1\xfb\x1a,..\x0a\xe4\x1e\xf0a\xbeM9\x19+{\x92\xbf\xb6*;\xc8\x82M\x19\xaf\x96\xcaCf\xcf\xb1\x84\x0c\xa2\
\xfd\xa3\xd4\x9f\x89~\xb8\xad\xeb9\xf7\xbe\x0c\xf70\xd4\xfe\xe0\x19\x01^q\x92\xb2\xbb\xaa_\xc1[\x17\xd1\xfe\xdc&\x97C\xa8\xee\xcb\
\x97\x88>M/\xd71\xe0~\xb6\xc6i\x0a\x03\x89\x14vLE\x14\x14\xb0\xfd\xaa\xba\x0ev\xcd\xffh\xd6\xad\xac\x00\x03\xfd\x12\x0c\xb4\xb0\xb8\
\xf3\xc2\xf2M\xef\xedQ(\xf3\xf2C\xac\x07\xcb\x83\x0eK\xd3\x9ax\xbb\xe3H\x041,Mq\xe6\x1aL|\xe3\xe0n>\x83\xd6i\x0c=\x9b\xeba,\xa1\xc9\
J\xdelF\xb9VI\xdfxfr;\xd9E\xa4\xad{Q\xc9gS)02\xbc\x82\x82\xfe\x1a\x1c\xeb\xdcB{\x1dk\xd3[#\xb1\xb8s\x90,\xe1\xe6\x9d\xcb\x91\xbc\x91\
\x17\xfc\x07\xb1^\x11v\xf8\xd4\x07@\x8a\x97;\x82'\xe0|\x02\xc6\x15\xc1\x0fp,";

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
			callback(err);
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
						callback(((byte1 - 192) << 8) + data2.readUInt8(0) + 192, binary);
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
						callback(data2.readUInt32(0), binary);
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
			callback(err);
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
								case 3: packetLength = data2.readUInt16(); break;
								case 4: packetLength = data2.readUInt32(); break;
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
 * @param keyBinaryStream {Readable Stream}
 * @param callback {Function} function(error, tag, header, body), where tag is the packet type, header the binary
 *                            data of the header and body the binary body data.
*/
function gpgsplit(keyBinaryStream, callback) {
	var read = utils.bufferReadableStream(keyBinaryStream);

	var readPacket = function() {
		getHeaderInfo(read, function(err, tag, packetLength, header) {
			if(err)
				callback(err);
			
			if(packetLength < 0) // Partial body length
			{
				read(-packetLength, function(err, body) {
					var readon = function() {
						read125OctetNumber(read, function(err, length) {
							if(err)
								callback(err);
							else
							{
								read(Math.abs(length), function(err, part) {
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
											callback(null, tag, header, body);
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
				read(packetLength === null ? -1 : packetLength, function(err, body) {
					if(err)
						callback(err);
					else
					{
						callback(null, tag, header, body);

						readPacket();
					}
				});
			}
		});
	};

	readPacket();
}

function getKeyInfo(keyBinaryStream) {
	
}

function getKeyInfo(keyBinary, callback) {
	utils.makeTempDir(function(err, dir, remove) {
		if(err)
			callback(err);
		else
		{
			var end = function(err) {
				remove();
				callback(err);
			};
			
			child_process.exec(config.gpgsplit, [ ], function(err, stdout, stderr) {
				if(err)
					end(err);
				
				fs.readdir(dir, function(err, files) {
					if(err)
						end(err);
					
					var keys = { };
					var lastKey = null;
					var lastIdentity = null;
					var lastAttribute = null;
					var lastSubkey = null;
					
					files.sort();
					files.forEach(function(it) {
						var m = it.match(/^\d{6}-(\d{3})\..*$/, it);
						if(m)
						{
							fs.readFile(dir+"/"+it, function(err, data) {
								if(err)
									; // TODO
								else
								{
									switch(m[1])
									{
										case "006": // Public key
											var key = extractPublicKeyInfo(
										case "013": // User ID

										case "014": // Public subkey

										case "017": // Attribute / Photo
										
										case "002": // Signature
	});
}

function listPackets(dataPiece, callback)
{
	var gpg = child_process.exec(config.gpg, [ "--list-packets" ], function(err, stdout, stderr) {
		if(err)
			callback(err);
		// Strip the info of the sample key
		var output = stdout.split(/^:/m);
		callback(null, output[2]);
	});
	
	// Write sample key first, as some data packets can only be analysed by gpg when a public key precedes them (no matter which one it is)
	gpg.stdin.write(SAMPLE_KEY);
	gpg.stdin.write(dataPiece);
	gpg.stdin.end();
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
				binary: data,
				attributes: { },
				signatures: { },
				identities: { }
			};
			var m = info.match(/^\s*keyid: (.*)\s*$/m);
			if(m)
				key.id = m[1];

			callback(null, key);
		}
	});
}

function extractUserIdInfo(data, callback)
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
	listPackets(data, function(err, info) {
		if(err)
			callback(err);
		else
		{
			var signature = {
				bykey: null,
				date: null,
				sigclass: null,
				binary: data
			};
			
			var m = info.match(/^\s*subpkt \d+ len \d+ \(issuer key ID (.*)\)\s*$/m);
			if(m)
				signature.bykey = m[1];
			m = info.match(/^\s*version \d+, created (\d+), md5len \d+, sigclass 0x([0-9a-f]+)\s*/m);
			if(m)
			{
				signature.date = new Date(m[1]*1000);
				signature.sigclass = parseInt(m[2], 16);
			}
			
			callback(signature);
		}
	});
}