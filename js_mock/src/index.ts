import fs from 'node:fs'

export namespace Ftp {
  export type Uid = number;
  export interface FileInfo {
    name: string;
    data: Uint8Array
  }

  export function upload(uid: Uid, file: FileInfo) {
    fs.writeFile()
  }
}