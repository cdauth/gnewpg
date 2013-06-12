var express = require("express");
var soynode = require("soynode");
var utils = require("../utils");
var sessions = require("../sessions");
var i18n = require("../i18n");
var config = require("../config");
var fs = require("fs");
var mails = require("../mails");
var async = require("async");
var db = require("../database");
var pgp = require("node-pgp");

function startServer(callback) {
	var app = express();

	if(config.trustProxy)
		app.enable("trust proxy");

	app.use(function(req, res, next) {
		res.soy = function(template, params) {
			_renderSoy(req, res, template, params);
		};
		res.redirectLogin = function() {
			res.redirect(303, config.baseurl + "/login?referer=" + encodeURIComponent(req.url))
		};
		res.sendError = function(code, message) {
			res.status(code);
			res.soy("error", { message: message });
		};

		next();
	});

	// Initialise debug actions before opening database connection etc.
	require("./actions/debug")(app);

	app.use(express.bodyParser({ uploadDir: config.tmpDir+"/upload", maxFieldsSize: config.maxUploadSize })); // For POST requests
	app.use(express.cookieParser());
	app.use(db.middleware);
	app.use(sessions.sessionMiddleware);
	app.use("/static", express.static(__dirname+"/static"));
	app.use(i18n.middleware);
	app.use(function(req, res, next) {
		if(req.method == "GET" || req.method == "HEAD")
			return next();

		utils.checkReferrer(req, res, next);
	});

	soynode.setOptions({
		"classpath" : __dirname+"/../soyFunctions/SoyFunctionsModule.jar",
		"pluginModules" : [ "gnewpg.SoyFunctionsModule" ],
		"additionalArguments" : [ "--isUsingIjData" ]
	});

	soynode.compileTemplates(__dirname+"/soy", function(err) {
		if(err)
			return callback(err);

		fs.readdir(__dirname+"/actions", function(err, list) {
			if(err)
				return callback(err);

			for(var i=0; i<list.length; i++)
				require(__dirname+"/actions/"+list[i])(app);

			if(config.address)
				app.listen(config.port, config.address);
			else
				app.listen(config.port);

			callback();
		});
	});
}

/*function _request(method, template) {
	var module = null;
	try {
		module = require.resolve("./"+template);
	} catch(e) {
		if(e.code != "MODULE_NOT_FOUND")
			throw e;
	}
	if(module)
		module = require(module);

	return function(req, res, next) {
		var send = function(err) {
			if(err)
				next(err);
			else
				res.send(soynode.render("gnewpg.pages."+template, req.params, i18n.injectMethods(req, { "req" : req })));
		};

		if(module && module[method])
			module[method](req, res, send);
		else
			send();
	};
}*/

function _renderSoy(req, res, template, params) {
	res.send(soynode.render("gnewpg.pages."+template, params || { }, i18n.injectMethods(req, { "req" : req, consts: pgp.consts })));
}

exports.startServer = startServer;