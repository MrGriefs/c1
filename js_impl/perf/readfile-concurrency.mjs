import fs from 'node:fs/promises'
import { performance } from 'node:perf_hooks';

async function testA(iterations) {
  let totalTime = 0;

  for (let i = 0; i != iterations; ++i) {
    const t0 = performance.now();
    await Promise.all([
      fs.readFile('./.ssl/ca.pem'),
      fs.readFile('./.ssl/dh1.pem'),
      fs.readFile('./.ssl/cert.pem'),
      fs.readFile('./.ssl/key.pem'),
    ]);
    const t1 = performance.now();
    totalTime += t1 - t0;
  }

  return totalTime;
}

async function testB(iterations) {
  let totalTime = 0;

  for (let i = 0; i != iterations; ++i) {
    const t0 = performance.now();
    await fs.readFile('./.ssl/ca.pem');
    await fs.readFile('./.ssl/dh1.pem');
    await fs.readFile('./.ssl/cert.pem');
    await fs.readFile('./.ssl/key.pem');
    const t1 = performance.now();
    totalTime += t1 - t0;
  }

  return totalTime;
}

async function main() {
  const iterations = 1000;
  console.log(`Test A took ${await testA(iterations)} milliseconds over ${iterations} iterations.`);
  console.log(`Test B took ${await testB(iterations)} milliseconds over ${iterations} iterations.`);
}

main();