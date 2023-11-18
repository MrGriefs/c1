import RE2 from 're2';

/** RegExp/RE2 helper functions and caching */
export namespace Re2 {
  const cache = new Map<string, RE2>();

  export function get(expr: string): RE2 {
    return cache.get(expr);
  }

  export function add(expr: string): (
    | true /* success */
    | false /* bad expr */
  ) {
    if (cache.has(expr)) return true;

    let re: RE2 | undefined;

    try { re = new RE2(expr); }
    catch { return false; }

    cache.set(expr, re);
    return true;
  }

  export function remove(expr: string): void {
    cache.delete(expr);
  }
}