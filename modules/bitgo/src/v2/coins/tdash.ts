/**
 * @prettier
 */
import { BaseCoin, BitGoBase } from '@bitgo/sdk-core';
import * as utxolib from '@bitgo/utxo-lib';
import { Dash } from './dash';

export class Tdash extends Dash {
  constructor(bitgo: BitGoBase) {
    super(bitgo, utxolib.networks.dashTest);
  }

  static createInstance(bitgo: BitGoBase): BaseCoin {
    return new Tdash(bitgo);
  }

  getChain() {
    return 'tdash';
  }

  getFullName() {
    return 'Testnet Dash';
  }
}
