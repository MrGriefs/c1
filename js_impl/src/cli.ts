/**
 * @fileoverview
 * CLI for connecting and uploading to a dedicated DropServer
 */

import process from 'node:process'; // use explicit imports only
import fs from 'node:fs/promises';
import { FormData, request } from 'undici';

const argv = process.argv.slice(2);
let port: string | undefined;
let uid: string | undefined;
let addr = '127.0.0.1';
const files: string[] = []

/* namespace CollectArgs */ {
  /** @pure */
  function expect_one(name: string, i: number) {
    if (i == argv.length) {
      console.error(`--${name} expects 1 argument, got 0`);
      process.exit(1);
    }
  }

  for (let i = 0; i != argv.length; ++i) {
    const arg = argv[i];
    switch (arg) {
      case '-p':
      case '--port': {
        expect_one('port', i);
        port = argv[++i];
        break;
      }

      case '-a':
      case '--address': {
        expect_one('address', i);
        addr = argv[++i];
        break;
      }

      case '-u':
      case '--user': {
        expect_one('user', i);
        uid = argv[++i];
        break;
      }

      default: {
        // file paths expected
        files.push(arg);
        break;
      }
    }
  }
}

/* namespace PromptBadFiles */ {
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
