var express = require("express");
var soynode = require("soynode");
var utils = require("./utils");
var sessions = require("./sessions");
var urlmap = require("./urlmap");
var i18n = require("./i18n");
var config = require("./config");
var fs = require("fs");

if(!fs.existsSync(config.tmpDir))
	fs.mkdirSync(config.tmpDir, 0700);
if(!fs.existsSync(config.tmpDir+"/upload"))
	fs.mkdirSync(config.tmpDir+"/upload", 0700);

var app = express();

sessions.scheduleInactiveSessionCleaning();
app.use(express.bodyParser({ uploadDir: config.tmpDir+"/upload" })); // For POST requests
app.use(express.cookieParser());
app.use(sessions.sessionMiddleware);
app.use("/static", express.static(__dirname+"/static"));
app.use(i18n.middleware);

soynode.setOptions({
	"classpath" : __dirname+"/soy_gettext/SoyGettextModule.jar",
	"pluginModules" : [ "gnewpg.SoyGettextModule" ],
	"additionalArguments" : [ "--isUsingIjData" ]
});
soynode.compileTemplates(__dirname+"/pages", function(err) {
	if(err)
		throw err;

	app.listen(8888);
	
	console.log("Server started");
});

function request(method, template) {
	var module = null;
	try {
		module = require.resolve("./pages/"+template);
	} catch(e) {
		if(e.code != "MODULE_NOT_FOUND")
			throw e;
	}
	if(module)
		module = require(module);
	
	return function(req, res) {
		var send = function() {
			res.send(soynode.render("gnewpg.pages."+template, req.params, i18n.injectMethods(req, { "req" : req })));
		};
	
		if(module && module[method])
			module[method](req, res, send);
		else
			send();
	};
}

for(var i in urlmap.get)
	app.get(i, request("get", urlmap.get[i]));
for(var i in urlmap.post)
	app.post(i, request("post", urlmap.post[i]));