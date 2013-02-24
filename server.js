var express = require("express");
var soynode = require("soynode");
var utils = require("./utils");
var sessions = require("./sessions");
var urlmap = require("./urlmap.json");
var i18n = require("./i18n");
var config = require("./config.json");
var fs = require("fs");
var mails = require("./mails");
var async = require("async");
var db = require("./database");

if(!fs.existsSync(config.tmpDir))
	fs.mkdirSync(config.tmpDir, 0700);
if(!fs.existsSync(config.tmpDir+"/upload"))
	fs.mkdirSync(config.tmpDir+"/upload", 0700);

var app = express();

async.series([
	function(cb) {
		sessions.scheduleInactiveSessionCleaning();
		
		app.use(express.bodyParser({ uploadDir: config.tmpDir+"/upload", maxFieldsSize: config.maxUploadSize })); // For POST requests
		app.use(express.cookieParser());
		app.use(db.middleware);
		app.use(sessions.sessionMiddleware);
		app.use("/static", express.static(__dirname+"/static"));
		app.use(i18n.middleware);
		
		for(var i in urlmap.get)
			app.get(i, _request("get", urlmap.get[i]));
		for(var i in urlmap.post)
			app.post(i, _request("post", urlmap.post[i]));

		soynode.setOptions({
			"classpath" : __dirname+"/soyFunctions/SoyFunctionsModule.jar",
			"pluginModules" : [ "gnewpg.SoyFunctionsModule" ],
			"additionalArguments" : [ "--isUsingIjData" ]
		});

		soynode.compileTemplates(__dirname+"/pages", cb);
	}, function(cb) {
		mails.loadPrivateKey(cb);
	},
	db.initialise
], function(err) {
	if(err)
		throw err;

	app.listen(8888);
	
	console.log("Server started");
});

function _request(method, template) {
	var module = null;
	try {
		module = require.resolve("./pages/"+template);
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
}