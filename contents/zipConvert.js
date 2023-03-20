const zipDBConnection = require("./zipDBConnection")

const zipConvert = async (postalcode) => {
    try {
        const response = await zipDBConnection.raw(`SELECT * FROM ReportingDB.dbo.PostalCodeGeocoding WHERE POSTAL_CODE = '${postalcode}'`)
        return response[0]
    } catch (err) {
        console.log(err)
    }

}

module.exports = {zipConvert}