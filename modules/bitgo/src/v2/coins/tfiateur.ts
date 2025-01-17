/**
 * @prettier
 */
import { BaseCoin, BitGoBase } from '@bitgo/sdk-core';
import { FiatEur } from './fiateur';

export class TfiatEur extends FiatEur {
  static createInstance(bitgo: BitGoBase): BaseCoin {
    return new TfiatEur(bitgo);
  }

  getChain() {
    return 'tfiateur';
  }

  getFullName() {
    return 'Testnet European Union Euro';
  }
}
