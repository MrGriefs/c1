import type { AddressInfo } from 'node:net';
import assert from 'node:assert';
import { Net } from './Util.js';

namespace _ {
  import E = Net.AddressType;

  type TestData = [address: string, expected: E, family?: `IPv${6 | 4}`];
  const tests: TestData[] = [
    ['0.0.0.0', E.Public],
    ['10.55.255.88', E.Private],
    ['192.168.1.55', E.Private],
    ['192.167.1.55', E.Public],
    ['172.18.1.55', E.Private],
    ['172.14.1.55', E.Public],
    ['::ffff:0.0.0.0', E.Public, 'IPv6'],
    ['::ffff:10.55.255.88', E.Private, 'IPv6'],
    ['::ffff:192.168.0.11', E.Private, 'IPv6'],
    ['::ffff:192.167.0.11', E.Public, 'IPv6'],
    ['::ffff:172.31.0.11', E.Private, 'IPv6'],
    ['::ffff:172.33.0.11', E.Public, 'IPv6'],
  ];

  for (const test of tests) {
    const info: AddressInfo = {
      address: test[0],
      family: test[2] ?? 'IPv4',
      port: 8080,
    };

    const res = Net.get_address_type(info);
    assert(res === test[1], `Failed on ${test}, expected ${test[1]} but got ${res}`);
  }
}