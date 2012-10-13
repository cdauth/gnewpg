var utils = require("./utils");
var mimelib = require("mimelib");

function Mime(contentType, body, headers, transferEncoding) {
	this.headers = headers || { };

	if(Array.isArray(body))
	{
		var boundary = "gnewpg-"+utils.generateRandomString(44);
		this.headers["Content-Type"] += "; boundary=\""+boundary+"\"";
		this.body = "";
		body.forEach(function(it) {
			this.body += "--"+boundary+"\r\n";
			this.body += it.toString()+"\r\n";
		});
		this.body += "--"+boundary+"--";
	}
	else
		this.body = body;

	if(transferEncoding == "quoted-printable")
	{
		this.headers["Content-Transfer-Encoding"] = "quoted-printable";
		this.body = mimelib.encodeQuotedPrintable(this.body);
	}
}

Mime.prototype.toString = function() {
	var ret = "";
	for(var i in this.headers)
		ret += mimelib.foldLine(i+": "+this.headers[i], 76, false, false, 52)+"\r\n";
	ret += "\r\n";
	ret += this.body;
	return ret;
};

module.exports = Mime;