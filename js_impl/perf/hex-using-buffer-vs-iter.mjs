import { performance } from 'node:perf_hooks';

const str = '7KjFpRt3sWnGv9Yz2QxHcVb5XmN6L8Zl1Dj4Pq7KtFwRyEzAhCDgGWahFWFiAWdn'

async function testA(iterations) {
  let totalTime = 0;

  for (let i = 0; i != iterations; ++i) {
    const t0 = performance.now();
    let hex = '';
    for (let i = 0; i != str.length; ++i)
      hex += str.charCodeAt(i).toString(16);
    const t1 = performance.now();
    totalTime += t1 - t0;
  }

  return totalTime;
}

async function testB(iterations) {
  let totalTime = 0;

  for (let i = 0; i != iterations; ++i) {
    const t0 = performance.now();
    let hex = Buffer.from(str).toString('hex');
    const t1 = performance.now();
    totalTime += t1 - t0;
  }

  return totalTime;
}

async function main() {
  const iterations = 100000;
  console.log(`Test A took ${await testA(iterations)} milliseconds over ${iterations} iterations.`);
  console.log(`Test B took ${await testB(iterations)} milliseconds over ${iterations} iterations.`);
}

main();