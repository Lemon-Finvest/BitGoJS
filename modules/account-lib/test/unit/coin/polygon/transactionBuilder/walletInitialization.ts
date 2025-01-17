import should from 'should';
import { TransactionType } from '@bitgo/sdk-core';
import { getBuilder, Polygon } from '../../../../../src';
import * as testData from '../../../../resources/polygon/polygon';

describe('Polygon wallet initialization', function () {
  let txBuilder: Polygon.TransactionBuilder;
  const initTxBuilder = (): void => {
    txBuilder = getBuilder('tpolygon') as Polygon.TransactionBuilder;
    txBuilder.fee({
      fee: '10000000000',
      gasLimit: '6800000',
    });
    txBuilder.counter(1);
    txBuilder.type(TransactionType.WalletInitialization);
  };

  describe('should build', () => {
    it('an init transaction', async () => {
      initTxBuilder();
      txBuilder.owner('0xe6c43626f11312de29b0011fa9da71ea3bba0e9f');
      txBuilder.owner('0x78caeb4527170e52f54d936e4eef6f83250e01bb');
      txBuilder.owner('0xb1938215967408fff7c59c77ae5e5283b55c8e26');
      txBuilder.sign({ key: testData.PRIVATE_KEY_1 });

      const tx = await txBuilder.build();

      tx.type.should.equal(TransactionType.WalletInitialization);
      const txJson = tx.toJson();
      txJson.gasLimit.should.equal('6800000');
      txJson.gasPrice.should.equal('10000000000');
      should.equal(txJson.nonce, 1);
      should.equal(txJson.chainId, '0x13881');
      should.equal(tx.toBroadcastFormat(), testData.TX_BROADCAST);
    });

    it('a signed init transaction from serialized', async () => {
      const newTxBuilder = getBuilder('tpolygon') as Polygon.TransactionBuilder;
      newTxBuilder.from(testData.TX_BROADCAST);
      const newTx = await newTxBuilder.build();
      should.equal(newTx.toBroadcastFormat(), testData.TX_BROADCAST);
      should.equal(newTx.id, '0xbadc4d3141830840dc109efc4cf023c3fcfdc471c6e35ef640a10616489416b6');
      const txJson = newTx.toJson();
      should.exist(txJson.v);
      should.exist(txJson.r);
      should.exist(txJson.s);
      should.exist(txJson.from);
    });

    it('a wallet initialization transaction with nonce 0', async () => {
      initTxBuilder();
      txBuilder.counter(0);
      txBuilder.owner('0xe6c43626f11312de29b0011fa9da71ea3bba0e9f');
      txBuilder.owner('0x78caeb4527170e52f54d936e4eef6f83250e01bb');
      txBuilder.owner('0xb1938215967408fff7c59c77ae5e5283b55c8e26');
      txBuilder.sign({ key: testData.PRIVATE_KEY_1 });
      const tx = await txBuilder.build();

      tx.type.should.equal(TransactionType.WalletInitialization);
      const txJson = tx.toJson();
      txJson.gasLimit.should.equal('6800000');
      txJson.gasPrice.should.equal('10000000000');
      should.equal(txJson.nonce, 0);
      should.equal(txJson.chainId, '0x13881');
    });

    it('an unsigned init transaction from serialized with 0-prefixed address', async () => {
      initTxBuilder();
      txBuilder.owner('0xe6c43626f11312de29b0011fa9da71ea3bba0e9f');
      txBuilder.owner('0x78caeb4527170e52f54d936e4eef6f83250e01bb');
      txBuilder.owner('0xb1938215967408fff7c59c77ae5e5283b55c8e26');
      const tx = await txBuilder.build();
      const serialized = tx.toBroadcastFormat();

      const newTxBuilder = getBuilder('tpolygon') as Polygon.TransactionBuilder;
      newTxBuilder.from(serialized);
      const newTx = await newTxBuilder.build();
      should.equal(newTx.toBroadcastFormat(), serialized);
    });

    it('an unsigned init transaction from serialized', async () => {
      initTxBuilder();
      txBuilder.owner('0xe6c43626f11312de29b0011fa9da71ea3bba0e9f');
      txBuilder.owner('0x78caeb4527170e52f54d936e4eef6f83250e01bb');
      txBuilder.owner('0xb1938215967408fff7c59c77ae5e5283b55c8e26');
      const tx = await txBuilder.build();
      const serialized = tx.toBroadcastFormat();

      const newTxBuilder = getBuilder('tpolygon') as Polygon.TransactionBuilder;
      newTxBuilder.from(serialized);
      const newTx = await newTxBuilder.build();
      should.equal(newTx.toBroadcastFormat(), serialized);
    });

    it('an unsigned transaction with final v check', async () => {
      initTxBuilder();
      txBuilder.owner('0xe6c43626f11312de29b0011fa9da71ea3bba0e9f');
      txBuilder.owner('0x78caeb4527170e52f54d936e4eef6f83250e01bb');
      txBuilder.owner('0xb1938215967408fff7c59c77ae5e5283b55c8e26');
      const tx = await txBuilder.build();
      should.equal(tx.toJson().v, '0x027125');
    });
  });
});
