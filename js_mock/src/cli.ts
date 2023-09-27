import process from 'node:process'; // use explicit imports only
import fs from 'node:fs/promises';
import { FormData, request } from 'undici';

const argv = process.argv.slice(2);
let port: string | undefined;
let uid: string | undefined;
let addr = '198.168.0.0';
const files: string[] = []

for (let i = 0; i < argv.length; ++i) {
  const arg = argv[i];
  switch (arg) {
    case '-p':
    case '--port': {
      if (i == argv.length) {
        console.error('--port expects 1 argument, got 0');
        process.exit(1);
      }

      const next = argv[++i];
      port = next;
      break;
    }

    case '-a':
    case '--address': {
      if (i == argv.length) {
        console.error('--address expects 1 argument, got 0');
        process.exit(1);
      }

      const next = argv[++i];
      addr = next;
      break;
    }

    case '-u':
    case '--user': {
      if (i == argv.length) {
        console.error('--user expects 1 argument, got 0');
        process.exit(1);
      }

      const next = argv[++i];
      uid = next;
      break;
    }

    default: {
      // file paths expected
      files.push(arg);
      break;
    }
  }
}

{
  // check if files readable in a parallel, non-blocking way
  const not_exist: string[] = [];
  const resolves = files.map(f =>
    fs.access(f, fs.constants.R_OK)
      .catch(e => {
        if (e.code !== 'ENOENT') throw e;
        not_exist.push(f);
      })
  );

  await Promise.all(resolves);

  if (not_exist.length !== 0) {
    console.error(`The following file paths do not exist:\n${not_exist.join('\n')}`);
    process.exit(1);
  }
}

if (undefined == port) {
  console.error('--port is a required argument');
  process.exit(1);
}

