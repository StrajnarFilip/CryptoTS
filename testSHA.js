"use strict";
setTimeout(function () {
    console.info("SHA");
    var bytes = BytesToPromise(new TextEncoder().encode("Hello"));
    var iterations = 200000;
    SHA512_times(bytes, iterations).then(function (x) { console.log("Iterations: " + iterations + ", result: " + x); });
}, 2000);
