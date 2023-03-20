
const distance = (start, finish) => {
	//"start" and "finish" are both objects formatted {lat: nn, lon: nn}

	const r = 6371e3; // metres
	const φ1 = (start.lat * Math.PI) / 180; // φ, λ in radians
	const φ2 = (finish.lat * Math.PI) / 180;
	const Δφ = ((finish.lat - start.lat) * Math.PI) / 180;
	const Δλ = ((finish.lon - start.lon) * Math.PI) / 180;

	const a =
		Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
		Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
	const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

	const d = (r * c) / 1609; // in metres

	return d
};

//Example/test>>
// distance(
// 	{ lat: 33.503704, lon: -112.053555 },
// 	{ lat: 33.424978, lon: -111.804532 }
// );

module.exports = { distance };
