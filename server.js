var express = require("express");
var soynode = require("soynode");
var utils = require("./utils");
var sessions = require("./sessions");
var urlmap = require("./urlmap");
var i18n = require("./i18n");

var app = express();

sessions.scheduleInactiveSessionCleaning();
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

for(var i in urlmap) {
	(function(url, template) {
		app.get(url, function(req, res) {
			try {
				require("pages/"+template)(req, res);
			} catch(e) {
				if(e.code != "MODULE_NOT_FOUND")
					throw e;
			}

			res.send(soynode.render("gnewpg.pages."+template, req.params, i18n.injectMethods(req, { "req" : req })));
		});
	})(i, urlmap[i]);
}