import type { AddressInfo } from 'node:net';

/**
 * "I Only Need O from T"  
 * 
 * type generic to make all fields of an object of type T optional except O fields.  
 * useful if you have a function that only require fields x, but not y or z,
 * without blocking the function user from using the same object of type T as the parameter.
 */
export type Only<T, O extends keyof T> = Required<Pick<T, O>> & Partial<Omit<T, O>>;

export function exhaust_match(_: never): Error {
  return new Error(`unexpected: ${_}`);
}

export namespace Fs {
  export function ignore_eexist(error) {
    if (error.code !== 'EEXIST') throw error;
  }

  export function ignore_enoent(error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

export namespace Net {
  export enum AddressType {
    Public,
    Private,
    NotSupported,
  }

  // reading interpolated strings in javascript is extremely slow.
  // this function is optimised to use indexes instead, since it
  // is called for every request
  export function get_address_type(info: AddressInfo): AddressType {
    const { address } = info;
    let index = 0;

    switch (info.family) {
      case 'IPv4': break;

      case 'IPv6': {
        const len = info.address.length;
        if (len === 2 || (len === 3 && info.address[2] === '1'))
          return AddressType.Private;

        index = '::ffff:'.length;
        break;
      }

      default: return AddressType.NotSupported;
    }

    // for private addresses, see https://datatracker.ietf.org/doc/html/rfc1918
    if (address[index] !== '1') return AddressType.Public;

    switch (address[++index]) {
      case '0':
        if (address[++index] === '.')
          return AddressType.Private;

        return AddressType.Public;

      case '7': {
        if (address[++index] !== '2')
          return AddressType.Public;

        // length of the second octet must be 2
        // index: 172.[1]6.0.0
        if (address[2 + (index += 2)] !== '.')
          return AddressType.Public;

        const octet = (+address[index++] * 10) + +address[index];
        if (octet > 31 || octet < 16) return AddressType.Public;

        return AddressType.Private;
      }

      case '9': {
        if (
          address[++index] !== '2' ||
          address[index += 2] !== '1' ||
          address[++index] !== '6' ||
          address[++index] !== '8'
        )
          return AddressType.Public;

        return AddressType.Private;
      }

      default: return AddressType.Public;
    }
  }
}
