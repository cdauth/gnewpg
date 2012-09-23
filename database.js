var pg = require("pg");
var pgUtils = require("pg/lib/utils");
var pgQuery = require("pg/lib/query");
var utils = require("./utils");
var config = require("./config");
var pgp = require("node-pgp");

var origPrepareValue = pgUtils.prepareValue;
pgUtils.prepareValue = function(val) {
	if(val instanceof Buffer) // For binary fields until https://github.com/brianc/node-postgres/pull/92 is fixed
	{
		var esc = "";
		for(var i=0; i<val.length; i++)
		{
			var char = val.readUInt8(i).toString(8);
			if(char.length == 1)
				esc += "\\00"+char;
			else if(char.length == 2)
				esc += "\\0"+char;
			else
				esc += "\\"+char;
		}
		return esc;
	}

	return origPrepareValue.apply(pgUtils, arguments);
}

var origHandleError = pgQuery.prototype.handleError;
pgQuery.prototype.handleError = function(err) {
	console.warn("SQL error", err, this);
	
	return origHandleError.apply(this, arguments);
};

function getConnection(callback) {
	pg.connect(config.db, callback);
}

function getConnection_(con, callback) {
	if(con)
		callback(null, con);
	else
		getConnection(callback);
}

function query(query, args, callback, con) {
	getConnection_(con, function(err, con) {
		if(err)
			callback(err);
		else
			con.query(query, args, callback);
	});
}

function query1(queryStr, args, callback, con) {
	query(queryStr, args, function(err, res) {
		if(err)
			callback(err);
		else if(res.rowCount < 1)
			callback(null, null);
		else
			callback(null, res.rows[0]);
	}, con);
}

function fifoQuery(query, args, callback, con) {
	getConnection_(con, function(err, con) {
		if(err)
			callback(err);
		else
			callback(null, getQueryFifo(con.query(query, args)));
	});
}

function getUniqueRandomString(length, table, field, callback, con) {
	getConnection_(con, function(err, con) {
		if(err) { callback(err); return; }

		var randomStr = utils.generateRandomString(length);
		con.query("SELECT "+field+" FROM "+table+" WHERE "+field+" = $1 LIMIT 1", [ randomStr ], function(err, res) {
			if(err)
				callback(err);
			else if(res.length > 0)
				getUniqueRandomString(length, table, field, callback, con);
			else
				callback(null, randomStr);
		});
	});
}

function getQueryFifo(queryObj) {
	var ret = new pgp.Fifo();
	
	queryObj.on("row", function(row) {
		ret._add(row);
	});
	
	queryObj.on("error", function(err) {
		ret._end(err);
	});
	
	queryObj.on("end", function() {
		ret._end();
	});
	
	return ret;
}

function xExists(table, idAttrs, callback, con) {
	getWithFilter('SELECT COUNT(*) AS n FROM "'+table+'"', idAttrs, function(err, res) {
		if(err)
			callback(err);
		else
			callback(null, !!res.n);
	}, true, con);
}

function getWithFilter(query, filter, callback, justOne, con) {
	var args = [ ];

	if(filter && Object.keys(filter).length > 0)
	{
		query += ' WHERE ';
		var first = true;
		var i = args.length+1;
		for(var j in filter)
		{
			if(first)
				first = false;
			else
				query += ' AND ';

			if(Array.isArray(filter[j]))
			{
				query += '"'+j+'" IN (';
				filter[j].forEach(function(it, k) {
					if(k > 0)
						query += ', ';
					query += '$'+(i++);
					args.push(it);
				});
				query += ')';
			}
			else
			{
				query += '"'+j+'" = $'+(i++);
				args.push(filter[j]);
			}
		}
	}
	
	if(justOne)
	{
		query += ' LIMIT 1';
		query1(query, args, callback, con);
	}
	else
		fifoQuery(query, args, callback, con);
	
}

exports.getConnection = getConnection;
exports.query = query;
exports.getUniqueRandomString = getUniqueRandomString;
exports.getQueryFifo = getQueryFifo;
exports.query1 = query1;
exports.fifoQuery = fifoQuery;
exports.xExists = xExists;
exports.getWithFilter = getWithFilter;