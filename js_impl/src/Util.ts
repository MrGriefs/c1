export namespace Fs {
  export function ignore_eexist(error) {
    if (error.code !== 'EEXIST') throw error;
  }

  export function ignore_enoent(error) {
    if (error.code !== 'EEXIST') throw error;
  }
}