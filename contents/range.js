
const range = async (start, distance, bearing = 0, coordlist = []) => {
    const radius = 6371e3
    const δ = distance / radius
    const θ = bearing * Math.PI / 180
    const φ = start.lat * Math.PI / 180
    const λ = start.lon * Math.PI / 180
    const φ2 = Math.asin(Math.sin(φ) * Math.cos(δ) + Math.cos(φ) * Math.sin(δ) * Math.cos(θ))
    let λ2 = λ + Math.atan2(Math.sin(θ) * Math.sin(δ) * Math.cos(φ), Math.cos(δ) - Math.sin(φ) * Math.sin(φ2))
    λ2 = (λ2 + 3 * Math.PI) % (2 * Math.PI) - Math.PI
    if (bearing <= 360) {
        coordlist.push({bear: bearing,  lat: φ2 * 180 / Math.PI, lon: λ2 * 180 / Math.PI})
        return range(start, distance, bearing + 1, coordlist)
    }
    // console.log(coordlist)
    return coordlist
}

module.exports = { range }