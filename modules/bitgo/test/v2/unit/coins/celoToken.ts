import 'should';

import { TestBitGo } from '@bitgo/sdk-test';
import { BitGo } from '../../../../src/bitgo';

describe('Celo Token:', function () {
  let bitgo;
  let celoTokenCoin;
  const tokenName = 'tcusd';

  before(function () {
    bitgo = TestBitGo.decorate(BitGo, { env: 'test' });
    bitgo.initializeTestVars();
    celoTokenCoin = bitgo.coin(tokenName);
  });

  it('should return constants', function () {
    celoTokenCoin.getChain().should.equal('tcusd');
    celoTokenCoin.getBaseChain().should.equal('tcelo');
    celoTokenCoin.getFullName().should.equal('Celo Token');
    celoTokenCoin.getBaseFactor().should.equal(1e18);
    celoTokenCoin.type.should.equal(tokenName);
    celoTokenCoin.name.should.equal('Test Celo USD Token');
    celoTokenCoin.coin.should.equal('tcelo');
    celoTokenCoin.network.should.equal('Testnet');
    celoTokenCoin.decimalPlaces.should.equal(18);
  });
});
