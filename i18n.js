var gettextModule = require("gettext");
var i18n_middleware = require("connect-i18n")({ default_locale: "en-gb" });
var node_util = require("util");
var dateformat = require("dateformat");
var utils = require("./utils");
var markdown = require("node-markdown").Markdown;
var sprintf = require("sprintf").sprintf;
var pgp = require("node-pgp");
var config = require("./config.json");

gettextModule.loadLocaleDirectory(__dirname+"/locale");

function gettext(msg, locale) {
	gettextModule.setlocale("LC_ALL", locale);

	if(msg instanceof Date)
		return dateformat(msg, gettext("isoUtcDateTime", msg));
	else if(msg instanceof I18nError)
		return msg.translate(function(msg) { return gettext.apply(null, [ msg, locale ].concat(pgp.utils.toProperArray(arguments).slice(1))); });
	else if(typeof msg == "string")
	{
		var args = [ gettextModule.gettext(msg) ];
		for(var i=2; i<arguments.length; i++)
			args.push(arguments[i]);
		return sprintf.apply(null, args);
	}
	else
		return msg;
}

function ngettext(msg1, msg2, n, locale) {
	gettextModule.setlocale("LC_ALL", locale);
			
	var args = [ gettextModule.ngettext(msg1, msg2, n) ];
	for(var i=4; i<arguments.length; i++)
		args.push(arguments[i]);
	return sprintf.apply(null, args);
}

function mdgettext(msg, locale) {
	var msg = gettext.apply(this, arguments);
	return markdown(msg);
}

function getLanguageForLocaleList(list) {
	for(var i=0; i<list.length; i++)
	{
		for(var j in gettextModule.data)
		{
			if(j.toLowerCase() == list[i].toLowerCase())
				return j;
		}
	}
	return "en";
}

function middleware(req, res, next) {
	i18n_middleware(req, res, function() {
		req.locale = getLanguageForLocaleList(req.locales);
		
		req.gettext = function(msg) {
			return gettext.apply(null, [ msg, req.locale ].concat(pgp.utils.toProperArray(arguments).slice(1)));
		};
		
		req.ngettext = function(msg1, msg2, n) {
			return ngettext.apply(null, [ msg1, msg2, n, req.locale ].concat(pgp.utils.toProperArray(arguments).slice(3)));
		};
		
		req.mdgettext = function(msg) {
			return mdgettext.apply(null, [ msg, req.locale ].concat(pgp.utils.toProperArray(arguments).slice(1)));
		};
		
		req.formatFingerprint = function(str) {
			var ret = [ ];
			for(var i = 0; i<str.length; i+=4)
				ret.push(str.substr(i, 4));
			return { contentKind : 0, content : "<span class=\"fingerprint\">"+ret.join("&nbsp;")+"</span>", toString: function() { return ret.join("\u00a0"); } };
		};
		
		req.formatKeyId = function(keyId) {
			var p1 = keyId.substr(0, 8);
			var p2 = keyId.substr(8, 16);
			return { contentKind : 0, content : "<span class=\"keyid\">"+p1+"&nbsp;<strong>"+p2+"</strong></span>", toString: function(){ return p1+"\u2009"+p2; } };
		};

		next();
	});
}

function injectMethods(req, toObj) {
	toObj._ = toObj.gettext = req.gettext;
	toObj.ngettext = req.ngettext;
	toObj.mdgettext = req.mdgettext;
	toObj.formatFingerprint = req.formatFingerprint;
	toObj.formatKeyId = req.formatKeyId;
	toObj.consts = pgp.consts;
	toObj.config = config;

	return toObj;
}

function I18nError(msgId) {
	function _(str) { return str; }

	if(msgId instanceof I18nError)
		this.args = msgId.args;
	else if(typeof msgId == "string")
		this.args = arguments;
	else
	{
		console.warn("Internal error", msgId);
		this.args = [ _("Internal error") ];
	}
	
	this.translate = function(gettext) {
		return gettext.apply(null, this.args);
	};
}

exports.middleware = middleware;
exports.injectMethods = injectMethods;
exports.Error_ = I18nError;