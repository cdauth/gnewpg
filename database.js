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

function getEntries(table, fields, filter, suffix, callback, con) {
	if(suffix == null) {
		con = callback;
		callback = suffix;
	}
	
	var args = [ ];
	var q = 'SELECT ';
	if(Array.isArray(fields))
		q += '"'+fields.join('", "')+'"';
	else
		q += fields;
	q += ' FROM "'+table+'";

	var filter = _filterToCondition(filter);
	if(filter)
	{
		q += ' '+filter.condition;
		args = args.concat(filter.args);
	}
	
	if(suffix)
		q += ' '+suffix;
	
	fifoQuery(q, args, callback, con);
}

function getEntry(table, fields, filter, callback, con) {
	var args = [ ];
	var q = 'SELECT ';
	if(fields == null)
		q += 'COUNT(*) AS n';
	else if(Array.isArray(fields))
		q += '"'+fields.join('", "')+'"';
	else
		q += fields;
	q += ' FROM "'+table+'";

	var filter = _filterToCondition(filter);
	if(filter)
	{
		q += ' '+filter.condition;
		args = args.concat(filter.args);
	}
	
	q += ' LIMIT 1';
	
	if(fields != null)
		query1(q, args, callback, con);
	else
	{
		query1(q, args, function(err, res) {
			if(err)
				callback(err);
			else
				callback(null, res.n > 0);
		}, con);
	}
}

function entryExists(table, filter, callback, con) {
	getEntry(table, null, filter, callback, con);
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
	
	var filter = _filterToCondition(filter);
	if(filter)
	{
		q += ' '+filter.condition;
		args = args.push(filter.args);
	}
	
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
	
	var filter = _filterToCondition(filter);
	if(filter)
	{
		q += ' '+filter.condition;
		args = args.concat(filter.args);
	}
	
	query(q, args, callback, con);
}

function xExists(table, idAttrs, callback, con) {
	getWithFilter('SELECT COUNT(*) AS n FROM "'+table+'"', idAttrs, function(err, res) {
		if(err)
			callback(err);
		else
			callback(null, !!res.n);
	}, true, con);
}

function _filterToCondition(filter) {
	if(!filter || Object.keys(filter).length == 0)
		return null;

	var condition = "";
	var args = [ ];
	var i = 1;
	var first = true;
	for(var j in filter)
	{
		if(first)
			first = false;
		else
			condition += ' AND ';

		if(Array.isArray(filter[j]))
		{
			condition += '"'+j+'" IN (';
			filter[j].forEach(function(it, k) {
				if(k > 0)
					condition += ', ';
				condition += '$'+(i++);
				args.push(it);
			});
			condition += ')';
		}
		else
		{
			condition += '"'+j+'" = $'+(i++);
			args.push(filter[j]);
		}
	}
	
	return { condition: condition, args: args };
}

function getWithFilter(query, filter, callback, justOne, con) {
	var args = [ ];

	var filter = _filterToCondition(filter);
	if(filter)
	{
		query += ' WHERE '+filter.condition;
		args = args.concat(filter.args);
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
exports.getEntries = getEntries;
exports.getEntry = getEntry;
exports.entryExists = entryExists;
exports.update = update;
exports.insert = insert;
exports.remove = remove;
exports.delete = remove;