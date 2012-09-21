var gettext = require("gettext");
var i18n_middleware = require("connect-i18n")({ default_locale: "en-gb" });
var node_util = require("util");

gettext.loadLocaleDirectory(__dirname+"/locale");

function getLanguageForLocaleList(list) {
	for(var i=0; i<list.length; i++)
	{
		for(var j in gettext.data)
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
			gettext.setlocale("LC_ALL", req.locale);
			
			var args = [ gettext.gettext(msg) ];
			for(var i=1; i<arguments.length; i++)
				args.push(arguments[i]);
			
			return node_util.format.apply(node_util, args); // sprintf
		};
		
		req.ngettext = function(msg1, msg2, n) {
			gettext.setlocale("LC_ALL", req.locale);
			
			var args = [ gettext.ngettext(msg1, msg2, n) ];
			for(var i=3; i<arguments.length; i++)
				args.push(arguments[i]);
			
			return node_util.format.apply(node_util, args); // sprintf
		};

		next();
	});
}

function injectMethods(req, toObj) {
	toObj._ = toObj.gettext = req.gettext;
	toObj.ngettext = req.ngettext;

	return toObj;
}

function I18nError(msgId) {
	this.args = arguments;
	
	this.translate = function(gettext) {
		return gettext.apply(null, arguments);
	};
}

exports.middleware = middleware;
exports.injectMethods = injectMethods;
exports.Error = I18nError;