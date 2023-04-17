a simple dependency-free geographic distance and range calculator.

# use
### run 
`npm install geodisco`

### script
```
const geodisco = require('geodisco')

const distanceInMeters = geodisco.distance(33.716265, -112.324609, 44.729307, -94.485257)
const circularRangeCoordinates = geodisco.range(33.716265, -112.324609, 5000)

console.log(distanceInMeters)
console.log(circularRangeCoordinates)
```

### practical application
my use case for this thing was to sidestep the use of Google Distance Matrix API for calculating distance from customer location and store location in ecommerce contexts. This calculates linear distance, so its not going to be particularly useful if your customer and store are on either side of a mountain/ocean/chasm but unlike conventional point to point distance calculations, it accommodates geography by assuming the points are on the surface of a earth sized sphere (i.e. earth) instead of a plane.