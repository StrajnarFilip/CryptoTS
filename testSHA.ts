setTimeout(() => {
    console.info("SHA")

    const bytes = BytesToPromise(new TextEncoder().encode("Hello"))
    const iterations = 200000;
    SHA512_times(bytes, iterations).then((x) => { console.log(`Iterations: ${iterations}, result: ${x}`) })
}, 2000)

