import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';

let __FTP_STARTED__: boolean;

export namespace Ftp {
  export type Uid = string;
  export interface FileInfo {
    path: string;
    data: Buffer;
  }

  export async function upload(uid: Uid, file: FileInfo) {
    await fs.writeFile(path.join(uid, file.path), file.data);
  }

  export function create(storePath: string) {
    if (__FTP_STARTED__ == true)
      throw new Error('ftp server was already started');
    __FTP_STARTED__ = true;

    return http.createServer((req, res) => {
      if (req.url !== '/')
        return void res
          .writeHead(404)
          .end();
      
      
    })
  }
}