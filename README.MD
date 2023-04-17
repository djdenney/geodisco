a simple dependency-free geographic distance and range calculator.

#use
run `npm install geodistcalc`

script
```
const geodistcalc = require('geodistcalc')

const distanceInMeters = geodistcalc.distance(33.716265, -112.324609, 44.729307, -94.485257)
const circularRangeCoordinates = geodistcalc.range(33.716265, -112.324609, 5000)

console.log(distanceInMeters)
console.log(circularRangeCoordinates)
```