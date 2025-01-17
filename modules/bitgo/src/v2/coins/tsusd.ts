/**
 * @prettier
 */
import { BaseCoin, BitGoBase } from '@bitgo/sdk-core';
import { Susd } from './susd';

export class Tsusd extends Susd {
  static createInstance(bitgo: BitGoBase): BaseCoin {
    return new Tsusd(bitgo);
  }

  getChain() {
    return 'tsusd';
  }

  getFullName() {
    return 'Test Silvergate USD';
  }
}
