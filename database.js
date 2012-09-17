var pg = require("pg");
var utils = require("./utils");
var config = require("./config");

function getConnection(callback) {
	pg.connect(config.db, function(err, con) {
		callback(err, con);
	});
}

function getUniqueRandomString(length, table, field, callback, connection) {
	if(connection == null)
	{
		getConnection(function(err, con){
			if(err)
				callback(err);
			else
				getUniqueRandomString(length, table, field, callback, con);
		});
	}
	
	var randomStr = utils.generateRandomString(length);
	connection.query("SELECT "+field+" FROM "+table+" WHERE "+field+" = $1 LIMIT 1", [ randomStr ], function(err, res) {
		if(err)
			callback(err);
		else if(res.length > 0)
			getUniqueRandomString(length, table, field, callback, connection);
		else
			callback(null, randomStr);
	});
}

exports.getConnection = getConnection;
exports.getUniqueRandomString = getUniqueRandomString;