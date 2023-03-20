const zipDBConnection = require("knex")({
    client: "mssql",
    connection: {
        server: process.env.REP_DB_MACHINE,
        user: process.env.REP_DB_USERNAME,
        password: process.env.REP_DB_PASSWORD,
        database: 'ReportingDB',
        options: {
            port: 1433,
        },
        acquireConnectionTimeout: 6000000,
    }
})

module.exports = zipDBConnection