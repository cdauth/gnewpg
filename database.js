var utils = require("./utils");
var config = require("./config");
var pgp = require("node-pgp");
var pgKeyring = require("node-pgp-postgres");
var pgKeyringDatabase = require("node-pgp-postgres/lib/database");
var pgKeyringStructure = require("node-pgp-postgres/lib/structure");
var async = require("async");
var fs = require("fs");

function initialise(callback) {
	async.series([
		async.apply(pgKeyring.initialiseDatabase, config.db),
		function(next) {
			fs.readFile(__dirname+"/database.sql", "utf8", function(err, queries) {
				if(err)
					return next(err);

				getConnection(function(err, con) {
					if(err)
						return callback(err);

					pgKeyringStructure._createStructure(con, queries, function(err) {
						con.done();
						next(err);
					});
				});
			});
		}
	], callback);
}

function getConnection(callback) {
	pgKeyringDatabase.getConnection(config.db, callback);
}

function _getConnections() {
	return pgKeyringDatabase._getConnections();
}

function middleware(req, res, next) {
	getConnection(function(err, con) {
		if(err)
			return next(err);

		req.dbCon = con;

		var endBkp = res.end;
		res.end = function() {
			con.done();

			endBkp.apply(this, arguments);
		};

		next();
	});
}

function getUniqueRandomString(con, length, table, field, callback) {
	var randomStr = pgp.utils.generateRandomString(length).toLowerCase();
	con.query("SELECT "+field+" FROM "+table+" WHERE "+field+" = $1 LIMIT 1", [ randomStr ], function(err, res) {
		if(err)
			callback(err);
		else if(res.length > 0)
			getUniqueRandomString(con, length, table, field, callback);
		else
			callback(null, randomStr);
	});
}

module.exports = utils.extend({ }, pgKeyringDatabase);
module.exports.initialise = initialise;
module.exports.getConnection = getConnection;
module.exports.middleware = middleware;
module.exports.getUniqueRandomString = getUniqueRandomString;
module.exports._getConnections = _getConnections;