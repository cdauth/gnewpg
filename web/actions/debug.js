var config = require("../../config");
var database = require("../../database");

module.exports = function(app) {
	if(!config.debug)
		return;

	app.get("/debug", _showDebug);
};

function _showDebug(req, res, next) {
	var connections = database._getConnections();
	var params = { connections: [ ] };
	for(var i in connections) {
		params.connections.push(connections[i].stack);
	}

	res.soy("debug", params);
}