const mysql = require("mysql");
const util = require("util"); 
let manhDBConnection;

manhDBConnection = mysql.createConnection({
    host: process.env.MAO_DB_MACHINE,
    user: process.env.MAO_USERNAME,
    password: process.env.MAO_PASSWORD,
});

manhDBConnection.query = util.promisify(manhDBConnection.query).bind(manhDBConnection);

manhDBConnection.connect(function(err){
    if (err) {
        console.log("error connecting: " + err.stack);
        return;
    };
    console.log("connected as... " + manhDBConnection.threadId);
});

module.exports = manhDBConnection;