/* this script runs about 100,000 calls to the Google Maps API to
update the ZIP database with new coordinates. 100,000 calls to the Google
Maps API costs about $500. The idea is to periodically use this script
to keep the ZIP code database updated, like once monthly or so. */

const zipDBConnection = require("./zipDBConnection")

const getAddPostalCodes = async (i = 600) => {
    try {
        const check = await zipDBConnection("PostalCodeGeoCoding").raw(`SELECT * FROM ReportingDB.dbo.PostalCodeGeoCoding WHERE POSTAL_CODE = '${i}'`)
        if (!check[0]) {
            console.log(`Postal Code ${i} already in Database`)
            return await getAddPostalCodes(i + 1)
        }
        const response = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?components=postal_code:${i}&key=${process.env.GCP_API_KEY}`)
        const responsedata = await response.json()
        await zipDBConnection("PostalCodeGeoCoding").insert({POSTAL_CODE: i, LATITUDE:responsedata.results[0].geometry.location.lat, LONGITUDE:responsedata.results[0].geometry.location.lng})
        if (i < 100000) {
            console.log(`Postal Code ${i} found `)
            return await getAddPostalCodes(i + 1)
        } else {
            process.exit()
        }
    } catch (err) {
        console.log(`Postal Code ${i} not found`)
        return await getAddPostalCodes(i + 1)
    }
}

module.exports = { getAddPostalCodes }