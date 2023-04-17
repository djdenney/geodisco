const distance = (slat, slon, elat, elon) => {
    const r = 6371e3;
    const φ1 = (slat * Math.PI) / 180;
    const φ2 = (elat * Math.PI) / 180;
    const Δφ = ((elat - slat) * Math.PI) / 180;
    const Δλ = ((elon - slon) * Math.PI) / 180;

    const a =
        Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
        Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    const d = r * c;
    console.log(`the distance between (${slat}, ${slon}) and (${elat}, ${elon}) is ${d} meters`)
    return d;
};

const range = (lat, lon, distance, bearing = 0, coordlist = []) => {
    const radius = 6371e3;
    const δ = distance / radius;
    const θ = (bearing * Math.PI) / 180;
    const φ = (lat * Math.PI) / 180;
    const λ = (lon * Math.PI) / 180;
    const φ2 = Math.asin(
        Math.sin(φ) * Math.cos(δ) + Math.cos(φ) * Math.sin(δ) * Math.cos(θ)
    );
    let λ2 =
        λ +
        Math.atan2(
            Math.sin(θ) * Math.sin(δ) * Math.cos(φ),
            Math.cos(δ) - Math.sin(φ) * Math.sin(φ2)
        );
    λ2 = ((λ2 + 3 * Math.PI) % (2 * Math.PI)) - Math.PI;
    if (bearing <= 360) {
        coordlist.push({
            bear: bearing,
            lat: (φ2 * 180) / Math.PI,
            lon: (λ2 * 180) / Math.PI,
        });
        return range(lat, lon, distance, bearing + 1, coordlist);
    }
    console.log(coordlist)
    return coordlist;
};

process.argv[2] === 'd' && distance(process.argv[3], process.argv[4], process.argv[5], process.argv[6])
process.argv[2] === 'r' && range(process.argv[3], process.argv[4], process.argv[5])