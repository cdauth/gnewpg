var pg = require("pg");
var utils = require("./utils");
var config = require("./config");

function getConnection(callback) {
	pg.connect(config.db, function(err, con) {
		callback(err, con);
	});
}

function getConnection_(con, callback) {
	if(con)
		callback(null, con);
	else
		getConnection(con, callback);
}

function query(query, args, callback, con) {
	getConnection_(con, function(err, con) {
		if(err)
			callback(err);
		else
			con.query(query, args, callback);
	}
}

function query1(query, args, callback, con) {
	query(query, args, function(err, res) {
		if(err)
			callback(err);
		else if(res.rowCount < 1)
			callback(null, null);
		else
			callback(null, res.rows[0]);
	});
}

function fifoQuery(query, args, callback, con) {
	getConnection_(con, function(err, con) {
		if(err)
			callback(err);
		else
			callback(null, getQueryFifo(con.query(query, args)));
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

function getQueryFifo(queryObj) {
	var ret = new pg.Fifo();
	
	queryObj.on("row", function(row) {
		ret._add(row);
	}
	
	queryObj.on("error", function(err) {
		ret._end(err);
	
	queryObj.on("end", function() {
		ret._end();
	}

exports.getConnection = getConnection;
exports.query = query;
exports.getUniqueRandomString = getUniqueRandomString;
exports.getQueryFifo = getQueryFifo;
exports.query1 = query1;
exports.fifoQuery = fifoQuery;