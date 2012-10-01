var pg = require("pg");
var pgUtils = require("pg/lib/utils");
var pgQuery = require("pg/lib/query");
var utils = require("./utils");
var config = require("./config");
var pgp = require("node-pgp");


// Fix writing of binary fields into the database
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


// Print SQL errors to stderr
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
			callback(null, _prepareQueryFifo(new pgp.Fifo(), con.query(query, args)));
	});
}

function fifoQuerySync(query, args, con) {
	var ret = new pgp.Fifo();
	getConnection_(con, function(err, con) {
		if(err)
			ret._end(err);
		else
			_prepareQueryFifo(ret, con.query(query, args));
	});
	return ret;
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

function _prepareQueryFifo(fifo, queryObj) {
	queryObj.on("row", function(row) {
		fifo._add(row);
	});
	
	queryObj.on("error", function(err) {
		fifo._end(err);
	});
	
	queryObj.on("end", function() {
		fifo._end();
	});
	
	return fifo;
}

function _getEntries(table, fields, filter, suffix) {
	var args = [ ];
	var q = 'SELECT ';
	if(Array.isArray(fields))
		q += '"'+fields.join('", "')+'"';
	else
		q += fields;
	q += ' FROM "'+table+'"';

	var filter = _filterToCondition(filter, args);
		q += ' WHERE '+filter;
	
	if(suffix)
		q += ' '+suffix;
	
	return { query: q, args: args };
}

function getEntries(table, fields, filter, suffix, callback, con) {
	if(typeof suffix == "function")
	{
		con = callback;
		callback = suffix;
		suffix = null;
	}

	var q = _getEntries(table, fields, filter, suffix);
	fifoQuery(q.query, q.args, callback, con);
}

function getEntriesSync(table, fields, filter, suffix, con) {
	if(typeof suffix == "object")
	{
		con = suffix;
		suffix = null;
	}

	var q = _getEntries(table, fields, filter, suffix);
	return fifoQuerySync(q.query, q.args, con);
}

function getEntriesAtOnce(table, fields, filter, suffix, callback, con) {
	if(typeof suffix == "function")
	{
		con = callback;
		callback = suffix;
		suffix = null;
	}

	var q = _getEntries(table, fields, filter, suffix);
	query(q.query, q.args, function(err, res) {
		if(err)
			callback(err);
		else
			callback(null, res.rows)
	}, con);
}

function getEntry(table, fields, filter, callback, con) {
	var q = _getEntries(table, fields, filter, "LIMIT 1");
	query1(q.query, q.args, callback, con);
}

function entryExists(table, filter, callback, con) {
	var q = _getEntries(table, "COUNT(*) AS n", filter, "LIMIT 1");
	query1(q.query, q.args, function(err, res) {
		if(err)
			callback(err);
		else
			callback(null, res.n > 0);
	}, con);
}

function update(table, fields, filter, callback, con) {
	var args = [ ];
	var q = 'UPDATE "'+table+'" SET ';
	
	var n = 1;
	for(var i in fields)
	{
		if(n > 1)
			q += ', ';
		q += '"'+i+'" = $'+(n++);
		args.push(fields[i]);
	}
	
	var filter = _filterToCondition(filter, args);
		q += ' WHERE '+filter;
	
	query(q, args, callback, con);
}

function insert(table, fields, callback, con) {
	var args = [ ];
	var q = 'INSERT INTO "'+table+'" ( ';
	var q2 = '';

	var n = 1;
	for(var i in fields)
	{
		if(n > 1)
		{
			q += ', ';
			q2 += ', ';
		}
		q += '"'+i+'"';
		q2 += '$'+(n++);
		args.push(fields[i]);
	}
	
	q += ' ) VALUES ( '+q2+' )';
	
	query(q, args, callback, con);
}

function remove(table, filter, callback, con) {
	var args = [ ];
	var q = 'DELETE FROM "'+table+'"';
	
	var filter = _filterToCondition(filter, args);
	if(filter)
		q += ' WHERE '+filter;
	
	query(q, args, callback, con);
}

function _filterToCondition(filter, args) {
	if(!filter || Object.keys(filter).length == 0)
		return null;

	var ret = "";
	var i = args.length+1;
	var first = true;
	for(var j in filter)
	{
		if(first)
			first = false;
		else
			ret += ' AND ';

		if(Array.isArray(filter[j]))
		{
			ret += '"'+j+'" IN (';
			filter[j].forEach(function(it, k) {
				if(k > 0)
					ret += ', ';
				ret += '$'+(i++);
				args.push(it);
			});
			ret += ')';
		}
		else if(filter[j] == null)
			ret += '"'+j+'" IS NULL';
		else
		{
			ret += '"'+j+'" = $'+(i++);
			args.push(filter[j]);
		}
	}
	
	return ret;
}

exports.getConnection = getConnection;
exports.query = query;
exports.getUniqueRandomString = getUniqueRandomString;
exports.query1 = query1;
exports.fifoQuery = fifoQuery;
exports.fifoQuerySync = fifoQuerySync;
exports.getEntries = getEntries;
exports.getEntriesSync = getEntriesSync;
exports.getEntriesAtOnce = getEntriesAtOnce;
exports.getEntry = getEntry;
exports.entryExists = entryExists;
exports.update = update;
exports.insert = insert;
exports.remove = remove;
exports.delete = remove;