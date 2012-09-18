var basicTypes = require("./basicTypes")
var BufferedStream = require("./bufferedStream")
var consts = require("./consts")

function getPacketInfo(tag, body, callback) {
	switch(tag)
	{
		case consts.PKT.PUBLIC_KEY:
			getKeyPacketInfo(body, callback);
			break;
		case consts.PKT.PUBLIC_SUBKEY:
			getSubkeyPacketInfo(body, callback);
			break;
		case consts.PKT.USER_ID:
			getIdentityPacketInfo(body, callback);
			break;
		case consts.PKT.ATTRIBUTE:
			getAttributePacketInfo(body, callback);
			break;
		case consts.PKT.SIGNATURE:
			getSignaturePacketInfo(body, callback);
			break;
		default:
			callback(new Error("Unsupported packet type"));
	}
}

function getKeyPacketInfo(body, callback)
{
	callback(null, {
		pkt: consts.PKT.PUBLIC_KEY,
		id: null,
		subkeys: { },
		attributes: { },
		signatures: { },
		identities: { },
		binary : body
	});
}

function getIdentityPacketInfo(body, callback)
{
	callback(null, body.substring(2));
}

function getSubkeyPacketInfo(body, callback)
{
	extractPublicKeyInfo(body, callback);
}

function getAttributePacketInfo(body, callback)
{
	callback(null, { pkt: consts.PKT.ATTRIBUTE });
}

function getSignaturePacketInfo(body, callback)
{
	var ret = {
		pkt : consts.PKT.SIGNATURE,
		type : null,
		date : null,
		issuer : null,
		pkalgo : null,
		hashalgo : null,
		version : null,
		binary : body,
		verified : false,
		hashedSubPackets : { },
		unhashedSubPackets : { },
		exportable : true,
		expiration : null
	};

	var byte1 = body.readUInt8(0);
	if(byte1 == 3)
	{ // Version 3 signature
		if(body.readUInt8(1) != 5)
			callback(new Error("Invalid signature data."));
		else
		{
			ret.type = body.readUInt8(2);
			ret.date = new Date(body.readUInt32BE(3));
			ret.issuer = body.toString("hex", 7, 15).toUpperCase();
			ret.pkalgo = body.readUInt8(16);
			ret.hashalgo = body.readUInt8(17);
			ret.version = 3;
			callback(null, ret);
		}
	}
	else if(byte1 == 4)
	{ // Version 4 signature
		ret.type = body.readUInt8(1);
		ret.pkalgo = body.readUInt8(2);
		ret.hashalgo = body.readUInt8(3);
		ret.version = 4;
		
		var hashedSubPacketsLength = body.readUInt16BE(4);
		var hashedSubPackets = body.slice(6, hashedSubPacketsLength+6);
		var unhashedSubPacketsLength = body.readUInt16BE(hashedSubPacketsLength+6);
		var unhashedSubPackets = body.slice(hashedSubPacketsLength+8, hashedSubPacketsLength+8+unhashedSubPacketsLength);
		extractSignatureSubPackets(hashedSubPackets, function(err, info1) {
			if(err) { callback(err); return; }
			
			ret.hashedSubPackets = info1;

			extractSignatureSubPackets(unhashedSubPackets, function(err, info2) {
				if(err) { callback(err); return; }
				
				ret.unhashedSubPackets = info2;
				
				if(ret.hashedSubPackets[consts.SIGSUBPKT.SIG_CREATED])
					ret.date = ret.hashedSubPackets[consts.SIGSUBPKT.SIG_CREATED][0].value;
				if(ret.hashedSubPackets[consts.SIGSUBPKT.ISSUER])
					ret.issuer = ret.hashedSubPackets[consts.SIGSUBPKT.ISSUER][0].value;
				else if(ret.unhashedSubPackets[consts.SIGSUBPKT.ISSUER])
					ret.issuer = ret.unhashedSubPackets[consts.SIGSUBPKT.ISSUER][0].value;
				if(ret.hashedSubPackets[consts.SIGSUBPKT.EXPORTABLE] && !ret.hashedSubPackets[consts.SIGSUBPKT.EXPORTABLE][0].value)
					ret.exportable = false;
				else if(ret.hashedSubPackets[consts.SIGSUBPKT.REV_KEY])
				{
					ret.hashedSubPackets[consts.SIGSUBPKT.REV_KEY].forEach(function(it) {
						if(it.value.sensitive)
							ret.exportable = false;
					});
				}

				callback(null, ret);
			});
		});
	}
	else
		callback(new Error("Unknown signature version "+byte1+"."));
}

function extractSignatureSubPackets(body, callback)
{
	var stream = new BufferedStream(body);
	
	var subPackets = { };
	
	var readon = function() {
		basicTypes.read125OctetNumber(stream, function(err, number) {
			if(err)
			{
				if(err.NOFIRSTBYTE)
					callback(null, subPackets);
				else
					callback(err);
				return;
			}
			
			if(number == 0)
			{
				readon();
				return;
			}
			
			stream.read(number, function(err, data2) {
				if(err) { callback(err); return; }

				var type = data2.readUInt8(0);
				var p = { critical : !!(type & consts.SIGSUBPKT.FLAG_CRITICAL), value: null, rawValue: data2.slice(1) };
				if(p.critical)
					type = type^consts.SIGSUBPKT.FLAG_CRITICAL;

				p.value = getValueForSignatureSubPacket(type, p.rawValue);

				if(!subPackets[type])
					subPackets[type] = [ ];
				subPackets[type].unshift(p);
				
				readon();
			});
		})
	};
	readon();
}

function getValueForSignatureSubPacket(type, binary) {
	switch(type)
	{
		case consts.SIGSUBPKT.SIG_CREATED:
			return new Date(binary.readUInt32BE(0)*1000);
		case consts.SIGSUBPKT.SIG_EXPIRE:
			return binary.readUInt16BE(0);
		case consts.SIGSUBPKT.EXPORTABLE:
		case consts.SIGSUBPKT.PRIMARY_UID:
		case consts.SIGSUBPKT.REVOCABLE:
			return !!binary.readUInt8(0);
		case consts.SIGSUBPKT.TRUST:
			return { level: binary.readUInt8(0), amount: binary.readUInt8(1) };
		case consts.SIGSUBPKT.REGEXP:
			var regexp = binary.toString("utf8", 0, binary.length);
			var idx = regexp.indexOf("\0");
			return (idx == -1 ? regexp : regexp.substr(0, idx));
		case consts.SIGSUBPKT.KEY_EXPIRE:
			return binary.readUInt32BE(0);
		case consts.SIGSUBPKT.PREF_SYM:
		case consts.SIGSUBPKT.PREF_HASH:
		case consts.SIGSUBPKT.PREF_COMPR:
			var prefs = [ ];
			for(var i=0; i<binary.length; i++)
				prefs.push(binary.readUInt8(i));
			return prefs;
		case consts.SIGSUBPKT.REV_KEY:
			var flags = binary.readUInt8(0);
			if(!(flags & 0x80))
				return null;
			return {
				sensitive : !!(flags & 0x40),
				pubkeyAlgo : binary.readUInt8(1),
				fingerprint : binary.toString("hex", 2, 22).toUpperCase()
			};
		case consts.SIGSUBPKT.ISSUER:
			return binary.toString("hex", 0, 8).toUpperCase();
		case consts.SIGSUBPKT.NOTATION:
			var flags = binary.readUInt32BE(0);
			var readable = !!(flags & 0x80000000);
			var nameLength = binary.readUInt16BE(1);
			var valueLength = binary.readUInt1BE(3);
			return {
				name: binary.toString("utf8", 5, 5+nameLength),
				value : readable ? binary.toString("utf8", 5+nameLength, 5+nameLength+valueLength) : binary.slice(5+nameLength, 5+nameLength+valueLength),
				flags : flags
			};
		case consts.SIGSUBPKT.KS_FLAGS:
			return { noModify : !!(binary.readUInt8(0) & 0x80) };
		case consts.SIGSUBPKT.PREF_KS:
		case consts.SIGSUBPKT.POLICY:
		case consts.SIGSUBPKT.SIGNERS_UID:
			return binary.toString("utf8", 0);
		case consts.SIGSUBPKT.KEY_FLAGS:
			var byte1 = binary.readUInt8(0);
			var ret = { };
			for(var i in consts.KEYFLAG)
				ret[consts.KEYFLAG[i]] = !!(byte1 & consts.KEYFLAG[i]);
			return ret;
		case consts.SIGSUBPKT.REVOC_REASON:
			return { code: binary.readUInt8(0), explanation: binary.toString("utf8", 1) };
		case consts.SIGSUBPKT.FEATURES:
			var byte1 = binary.readUInt8(0);
			var ret = { };
			for(var i in consts.FORMATS)
				ret[consts.FORMATS[i]] = !!(byte1 & consts.FORMATS[i]);
			return ret;
		//case consts.SIGSUBPKT.SIGNATURE:
};
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
			case consts.PKT.PUBLIC_KEY:
				lastKey = lastSubobject = null;
				extractKeyInfo(body, function(err, info) {
					if(err) { errors = true; return }

					if(!keys[info.id])
						keys[info.id] = info;
					lastkey = keys[info.id];

					next();
				});
				break;
			case consts.PKT.PUBLIC_SUBKEY:
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
						lastSubobjectType = "subkey";
						
						next();
					});
				}
				break;
			case consts.PKT.USER_ID:
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
			case consts.PKT.ATTRIBUTE:
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
			case consts.PKT.SIGNATURE:
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
		}
	}, function() {
		// All packets have beend handled
		callback(null, keys, errors);
	});
}

exports.getPacketInfo = getPacketInfo;
exports.getKeyPacketInfo = getKeyPacketInfo;
exports.getSubkeyPacketInfo = getSubkeyPacketInfo;
exports.getAttributePacketInfo = getAttributePacketInfo;
exports.getIdentityPacketInfo = getIdentityPacketInfo;
exports.getSignaturePacketInfo = getSignaturePacketInfo;