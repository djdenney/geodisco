console.time("run");
require("dotenv").config()
const manhDBConnection = require("./manhDBConnection");
const { storeQuery } = require("./storeQuery");
const { range } = require("./range");
const { distance } = require("./distance");
const { zipConvert } = require("./zipConvert");

const test = async (lat, lon, radius, postalcode) => {
    const converted = await zipConvert(postalcode)
    // console.log(converted)
    lat = converted.LATITUDE
    lon = converted.LONGITUDE
    // console.log(lat, lon)
    const coordlist = await range({ lat: lat, lon: lon }, (radius + 1) * 1609);
    // console.log(coordlist)
    const query = await storeQuery(coordlist);
    // console.log(query)
    const stores = await manhDBConnection.query(query);
    const distances = stores.reduce((a, b) => {
        const sd = distance(
            { lat: lat, lon: lon },
            { lat: b.LATITUDE, lon: b.LONGITUDE }
        );
        b.DISTANCE_IN_MILES = Math.floor(sd * 100) / 100;
        a.push(b);
        return a;
    }, []);
    const sorted = distances.sort((a, b) => a.DISTANCE_IN_MILES - b.DISTANCE_IN_MILES)
    sorted.forEach((store) => {
        console.log(`Store Number:\t${store.LOCATION_ID}\n\nAddress:\t${store.ADDRESS_ADDRESS1}\n\t\t${store.ADDRESS_CITY}, ${store.ADDRESS_STATE} ${store.ADDRESS_POSTALCODE}\n\nPhone Number:\t${store.ADDRESS_PHONE}\n\nDistance:\t${store.DISTANCE_IN_MILES} Miles\n\n-------\n\n`)
    })
    console.timeEnd("run");
    return distances;
};

test(null, null, 10, 85373);
