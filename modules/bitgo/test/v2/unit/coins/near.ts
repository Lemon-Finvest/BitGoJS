import should = require('should');
import * as accountLib from '@bitgo/account-lib';
import { TestBitGo } from '@bitgo/sdk-test';
import { BitGo } from '../../../../src/bitgo';
import { randomBytes } from 'crypto';
import { rawTx, accounts, validatorContractAddress, blockHash } from '../../fixtures/coins/near';
import * as _ from 'lodash';
import * as sinon from 'sinon';
import { Near } from '../../../../src/v2/coins/near';
import { Eos } from '../../../../src/v2/coins';
import { EosResponses } from '../../fixtures/coins/eos';

describe('NEAR:', function () {
  let bitgo;
  let basecoin;
  let newTxPrebuild;
  let newTxParams;
  const factory = accountLib.register('tnear', accountLib.Near.TransactionBuilderFactory);

  const txPrebuild = {
    txHex: rawTx.transfer.unsigned,
    txInfo: {},
  };

  const txParams = {
    recipients: [
      {
        address: '9f7b0675db59d19b4bd9c8c72eaabba75a9863d02b30115b8b3c3ca5c20f0254',
        amount: '1000000000000000000000000',
      },
    ],
  };

  before(function () {
    bitgo = TestBitGo.decorate(BitGo, { env: 'mock' });
    bitgo.initializeTestVars();
    basecoin = bitgo.coin('tnear');
    newTxPrebuild = () => {
      return _.cloneDeep(txPrebuild);
    };
    newTxParams = () => {
      return _.cloneDeep(txParams);
    };
  });

  it('should retun the right info', function () {
    const near = bitgo.coin('near');
    const tnear = bitgo.coin('tnear');

    near.getChain().should.equal('near');
    near.getFamily().should.equal('near');
    near.getFullName().should.equal('Near');
    near.getBaseFactor().should.equal(1e+24);

    tnear.getChain().should.equal('tnear');
    tnear.getFamily().should.equal('near');
    tnear.getFullName().should.equal('Testnet Near');
    tnear.getBaseFactor().should.equal(1e+24);
  });

  describe('Sign Message', () => {
    it('should be performed', async () => {
      const keyPair = new accountLib.Near.KeyPair();
      const messageToSign = Buffer.from(randomBytes(32)).toString('hex');
      const signature = await basecoin.signMessage(keyPair.getKeys(), messageToSign);
      keyPair.verifySignature(messageToSign, Uint8Array.from(signature)).should.equals(true);
    });

    it('should fail with missing private key', async () => {
      const keyPair = new accountLib.Near.KeyPair({ pub: '7788327c695dca4b3e649a0db45bc3e703a2c67428fce360e61800cc4248f4f7' }).getKeys();
      const messageToSign = Buffer.from(randomBytes(32)).toString('hex');
      await basecoin.signMessage(keyPair, messageToSign).should.be.rejectedWith('Invalid key pair options');
    });
  });

  describe('Sign transaction', () => {
    it('should sign transaction', async function () {
      const signed = await basecoin.signTransaction({
        txPrebuild: {
          txHex: rawTx.transfer.unsigned,
        },
        pubs: [
          accounts.account1.publicKey,
        ],
        prv: accounts.account1.secretKey,
      });
      signed.txHex.should.equal(rawTx.transfer.signed);
    });

    it('should fail to sign transaction with an invalid key', async function () {
      try {
        await basecoin.signTransaction({
          txPrebuild: {
            txHex: rawTx.transfer.unsigned,
          },
          pubs: [
            accounts.account2.publicKey,
          ],
          prv: accounts.account1.secretKey,
        });
      } catch (e) {
        should.equal(e.message, 'Private key cannot sign the transaction');
      }
    });

    it('should fail to build transaction with missing params', async function () {
      try {
        await basecoin.signTransaction({
          txPrebuild: {
            txHex: rawTx.transfer.unsigned,
            key: accounts.account1.publicKey,
          },
          prv: accounts.account1.secretKey,
        });
      } catch (e) {
        should.notEqual(e, null);
      }
    });
  });

  describe('Generate wallet key pair: ', () => {
    it('should generate key pair', () => {
      const kp = basecoin.generateKeyPair();
      basecoin.isValidPub(kp.pub).should.equal(true);
      basecoin.isValidPrv(kp.prv).should.equal(true);
    });

    it('should generate key pair from seed', () => {
      const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
      const kp = basecoin.generateKeyPair(seed);
      basecoin.isValidPub(kp.pub).should.equal(true);
      basecoin.isValidPrv(kp.prv).should.equal(true);
    });
  });

  describe('Verify transaction: ', () => {
    const amount = '1000000';
    const gas = '125000000000000';

    it('should succeed to verify unsigned transaction in base64 encoding', async () => {

      const txPrebuild = newTxPrebuild();
      const txParams = newTxParams();
      const verification = {};
      const isTransactionVerified = await basecoin.verifyTransaction({ txParams, txPrebuild, verification });
      isTransactionVerified.should.equal(true);
    });

    it('should succeed to verify signed transaction in base64 encoding', async () => {

      const txPrebuild = {
        txHex: rawTx.transfer.signed,
        txInfo: {},
      };

      const txParams = newTxParams();
      const verification = {};

      const isTransactionVerified = await basecoin.verifyTransaction({ txParams, txPrebuild, verification });
      isTransactionVerified.should.equal(true);
    });

    it('should fail verify transactions when have different recipients', async () => {

      const txPrebuild = newTxPrebuild();

      const txParams = {
        recipients: [
          {
            address: '9f7b0675db59d19b4bd9c8c72eaabba75a9863d02b30115b8b3c3ca5c20f0254',
            amount: '1000000000000000000000000',
          },
          {
            address: '9f7b0675db59d19b4bd9c8c72eaabba75a9863d02b30115b8b3c3ca5c20f0254',
            amount: '2000000000000000000000000',
          },
        ],
      };

      const verification = {};

      await basecoin.verifyTransaction({ txParams, txPrebuild, verification })
        .should.be.rejectedWith('Tx outputs does not match with expected txParams recipients');
    });

    it('should fail verify transactions when total amount does not match with expected total amount field', async () => {

      const explainedTx = {
        id: '5jTEPuDcMCeEgp1iyEbNBKsnhYz4F4c1EPDtRmxm3wCw',
        displayOrder: [
          'outputAmount',
          'changeAmount',
          'outputs',
          'changeOutputs',
          'fee',
          'type',
        ],
        outputAmount: '90000',
        changeAmount: '0',
        changeOutputs: [],
        outputs: [
          {
            address: '9f7b0675db59d19b4bd9c8c72eaabba75a9863d02b30115b8b3c3ca5c20f0254',
            amount: '1000000000000000000000000',
          },
        ],
        fee: {
          fee: '',
        },
        type: 0,
      };

      const stub = sinon.stub(accountLib.Near.Transaction.prototype, 'explainTransaction');
      const txPrebuild = newTxPrebuild();
      const txParams = newTxParams();
      const verification = {};
      stub.returns(explainedTx);

      await basecoin.verifyTransaction({ txParams, txPrebuild, verification })
        .should.be.rejectedWith('Tx total amount does not match with expected total amount field');
      stub.restore();
    });

    it('should succeed to verify transaction in hex encoding', async () => {

      const txParams = newTxParams();
      const txPrebuild = newTxPrebuild();
      const verification = {};

      const isTransactionVerified = await basecoin.verifyTransaction({ txParams, txPrebuild, verification });
      isTransactionVerified.should.equal(true);
    });

    it('should convert serialized hex string to base64', async function () {
      const txParams = newTxParams();
      const txPrebuild = newTxPrebuild();
      const verification = {};
      txPrebuild.txHex = Buffer.from(txPrebuild.txHex, 'base64').toString('hex');
      const validTransaction = await basecoin.verifyTransaction({ txParams, txPrebuild, verification });
      validTransaction.should.equal(true);
    });

    it('should verify when input `recipients` is absent', async function () {
      const txParams = newTxParams();
      txParams.recipients = undefined;
      const txPrebuild = newTxPrebuild();
      const validTransaction = await basecoin.verifyTransaction({ txParams, txPrebuild });
      validTransaction.should.equal(true);
    });

    it('should fail verify when txHex is invalid', async function () {
      const txParams = newTxParams();
      txParams.recipients = undefined;
      const txPrebuild = {};
      await basecoin.verifyTransaction({ txParams, txPrebuild })
        .should.rejectedWith('missing required tx prebuild property txHex');
    });

    it('should succeed to verify transactions when recipients has extra data', async function () {
      const txPrebuild = newTxPrebuild();
      const txParams = newTxParams();
      txParams.data = 'data';

      const validTransaction = await basecoin.verifyTransaction({ txParams, txPrebuild });
      validTransaction.should.equal(true);
    });

    it('should verify activate staking transaction', async function () {
      const txBuilder = factory.getStakingActivateBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();
      const txPrebuild = {
        txHex: txToBroadcastFormat,
      };
      const txParams = {
        recipients: [
          {
            address: 'lavenderfive.pool.f863973.m0',
            amount: '1000000',
          },
        ],
      };
      const validTransaction = await basecoin.verifyTransaction({ txParams, txPrebuild });
      validTransaction.should.equal(true);
    });

    it('should verify deactivate staking transaction', async function () {
      const txBuilder = factory.getStakingDeactivateBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();
      const txPrebuild = {
        txHex: txToBroadcastFormat,
      };
      const txParams = {
        recipients: [],
      };
      const validTransaction = await basecoin.verifyTransaction({ txParams, txPrebuild });
      validTransaction.should.equal(true);
    });

    it('should verify withdraw staking transaction', async function () {
      const txBuilder = factory.getStakingWithdrawBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();
      const txPrebuild = {
        txHex: txToBroadcastFormat,
      };
      const txParams = {
        recipients: [
          {
            address: '61b18c6dc02ddcabdeac56cb4f21a971cc41cc97640f6f85b073480008c53a0d',
            amount: '1000000',
          },
        ],
      };
      const validTransaction = await basecoin.verifyTransaction({ txParams, txPrebuild });
      validTransaction.should.equal(true);
    });
  });

  describe('Explain Transactions:', () => {
    const amount = '1000000';
    const gas = '125000000000000';

    it('should explain an unsigned transfer transaction', async function () {
      const explainedTransaction = await basecoin.explainTransaction({
        txPrebuild: {
          txHex: rawTx.transfer.signed,
        },
      });
      explainedTransaction.should.deepEqual({
        displayOrder: [
          'outputAmount',
          'changeAmount',
          'outputs',
          'changeOutputs',
          'fee',
          'type',
        ],
        id: '5jTEPuDcMCeEgp1iyEbNBKsnhYz4F4c1EPDtRmxm3wCw',
        type: 0,
        changeOutputs: [],
        changeAmount: '0',
        outputAmount: '1000000000000000000000000',
        outputs: [
          {
            address: '9f7b0675db59d19b4bd9c8c72eaabba75a9863d02b30115b8b3c3ca5c20f0254',
            amount: '1000000000000000000000000',
          },
        ],
        fee: {
          fee: '',
        },
      });
    });

    it('should explain a signed transfer transaction', async function () {
      const explainedTransaction = await basecoin.explainTransaction({
        txPrebuild: {
          txHex: rawTx.transfer.signed,
        },
      });
      explainedTransaction.should.deepEqual({
        displayOrder: [
          'outputAmount',
          'changeAmount',
          'outputs',
          'changeOutputs',
          'fee',
          'type',
        ],
        id: '5jTEPuDcMCeEgp1iyEbNBKsnhYz4F4c1EPDtRmxm3wCw',
        type: 0,
        changeOutputs: [],
        changeAmount: '0',
        outputAmount: '1000000000000000000000000',
        outputs: [
          {
            address: '9f7b0675db59d19b4bd9c8c72eaabba75a9863d02b30115b8b3c3ca5c20f0254',
            amount: '1000000000000000000000000',
          },
        ],
        fee: {
          fee: '',
        },
      });
    });

    it('should explain activate staking transaction', async function () {
      const txBuilder = factory.getStakingActivateBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();
      const explainedTransaction = await basecoin.explainTransaction({
        txPrebuild: {
          txHex: txToBroadcastFormat,
        },
      });
      explainedTransaction.should.deepEqual({
        displayOrder: [
          'outputAmount',
          'changeAmount',
          'outputs',
          'changeOutputs',
          'fee',
          'type',
        ],
        id: 'GpiLLaGs2Fk2bd7SQvhkJaZjj74UnPPdF7cUa9pw15je',
        type: 13,
        changeOutputs: [],
        changeAmount: '0',
        outputAmount: '1000000',
        outputs: [
          {
            address: 'lavenderfive.pool.f863973.m0',
            amount: '1000000',
          },
        ],
        fee: {
          fee: '',
        },
      });
    });

    it('should explain deactivate staking transaction', async function () {
      const txBuilder = factory.getStakingDeactivateBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();
      const explainedTransaction = await basecoin.explainTransaction({
        txPrebuild: {
          txHex: txToBroadcastFormat,
        },
      });
      explainedTransaction.should.deepEqual({
        displayOrder: [
          'outputAmount',
          'changeAmount',
          'outputs',
          'changeOutputs',
          'fee',
          'type',
        ],
        id: 'CDxPRP3DgHN8gYmRDagk5TRuX7fsCRYHcuqoNULyQPUW',
        type: 17,
        changeOutputs: [],
        changeAmount: '0',
        outputAmount: '0',
        outputs: [],
        fee: {
          fee: '',
        },
      });
    });

    it('should explain withdraw staking transaction', async function () {
      const txBuilder = factory.getStakingWithdrawBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();
      const explainedTransaction = await basecoin.explainTransaction({
        txPrebuild: {
          txHex: txToBroadcastFormat,
        },
      });
      explainedTransaction.should.deepEqual({
        displayOrder: [
          'outputAmount',
          'changeAmount',
          'outputs',
          'changeOutputs',
          'fee',
          'type',
        ],
        id: '52ZX8MUwmYc6WQ67riUBpmntkcSxxT5aKkJYt5CtCZub',
        type: 15,
        changeOutputs: [],
        changeAmount: '0',
        outputAmount: '1000000',
        outputs: [
          {
            address: '61b18c6dc02ddcabdeac56cb4f21a971cc41cc97640f6f85b073480008c53a0d',
            amount: '1000000',
          },
        ],
        fee: {
          fee: '',
        },
      });
    });

    it('should fail to explain transaction with missing params', async function () {
      try {
        await basecoin.explainTransaction({
          txPrebuild: {},
        });
      } catch (error) {
        should.equal(error.message, 'Invalid transaction');
      }
    });

    it('should fail to explain transaction with wrong params', async function () {
      try {
        await basecoin.explainTransaction({
          txPrebuild: {
            txHex: 'invalidTxHex',
          },
        });
      } catch (error) {
        should.equal(error.message, 'Invalid transaction');
      }
    });
  });

  describe('Parse Transactions:', () => {
    const TEN_MILLION_NEAR = '10000000000000000000000000000000';
    const ONE_MILLION_NEAR = '1000000000000000000000000';

    const amount = TEN_MILLION_NEAR;
    const gas = '125000000000000';

    const response1 = {
      address: '9f7b0675db59d19b4bd9c8c72eaabba75a9863d02b30115b8b3c3ca5c20f0254',
      amount: ONE_MILLION_NEAR,
    };

    const response2 = {
      address: 'lavenderfive.pool.f863973.m0',
      amount: TEN_MILLION_NEAR,
    };

    const response3 = {
      address: '61b18c6dc02ddcabdeac56cb4f21a971cc41cc97640f6f85b073480008c53a0d',
      amount: TEN_MILLION_NEAR,
    };

    it('should parse an unsigned transfer transaction', async function () {
      const parsedTransaction = await basecoin.parseTransaction({
        txPrebuild: {
          txHex: rawTx.transfer.unsigned,
        },
        feeInfo: {
          fee: '5000',
        },
      });

      parsedTransaction.should.deepEqual({
        inputs: [response1],
        outputs: [response1],
      });
    });

    it('should parse a signed transfer transaction', async function () {
      const parsedTransaction = await basecoin.parseTransaction({
        txPrebuild: {
          txHex: rawTx.transfer.signed,
        },
        feeInfo: {
          fee: '',
        },
      });

      parsedTransaction.should.deepEqual({
        inputs: [response1],
        outputs: [response1],
      });
    });

    it('should fail parse a signed transfer transaction when explainTransaction response is undefined', async function () {
      const stub = sinon.stub(Near.prototype, 'explainTransaction');
      stub.resolves(undefined);
      await basecoin.parseTransaction({
        txPrebuild: {
          txHex: rawTx.transfer.signed,
        },
        feeInfo: {
          fee: '',
        },
      })
        .should.be.rejectedWith('Invalid transaction');
      stub.restore();
    });

    it('should parse activate staking transaction', async function () {
      const txBuilder = factory.getStakingActivateBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();
      const parsedTransaction = await basecoin.parseTransaction({
        txPrebuild: {
          txHex: txToBroadcastFormat,
        },
      });

      parsedTransaction.should.deepEqual({
        inputs: [response2],
        outputs: [response2],
      });
    });

    it('should parse deactivate staking transaction', async function () {
      const txBuilder = factory.getStakingDeactivateBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();
      const parsedTransaction = await basecoin.parseTransaction({
        txPrebuild: {
          txHex: txToBroadcastFormat,
        },
      });

      parsedTransaction.should.deepEqual({
        inputs: [],
        outputs: [],
      });
    });

    it('should parse withdraw staking transaction', async function () {
      const txBuilder = factory.getStakingWithdrawBuilder();
      txBuilder
        .amount(amount)
        .gas(gas)
        .sender(accounts.account1.address, accounts.account1.publicKey)
        .receiverId(validatorContractAddress)
        .recentBlockHash(blockHash.block1)
        .nonce(1);
      txBuilder.sign({ key: accounts.account1.secretKey });
      const tx = await txBuilder.build();
      const txToBroadcastFormat = tx.toBroadcastFormat();

      const parsedTransaction = await basecoin.parseTransaction({
        txPrebuild: {
          txHex: txToBroadcastFormat,
        },
      });

      parsedTransaction.should.deepEqual({
        inputs: [response3],
        outputs: [response3],
      });
    });
  });
  describe('Recover Transactions:', () => {

    it('should recover a txn for non-bitgo recoveries', async function () {
      const userKey = '{"iv":"I8cx17GV2qZ9HKF5ITZS4g==","v":1,"iter":10000,"ks":256,"ts":64,"mode"\n' +
        ':"ccm","adata":"","cipher":"aes","salt":"0k+79wgoUDU=","ct":"adpZXywRNHhLMI\n' +
        'IDae6KoQh6XmyNIslINE7aTd/9khp1/mu4uioKrJl0fAWC4+DdWWrEOiXKipX9yqvB5udWTDfaW\n' +
        'nM+ySG15MQ0Qrx0k1TqsDaYFFtQaNv64BV1nmOJrrT6gp5TRq3nxssgLnwdDJl8JvuSHplCxwKF\n' +
        'PynXTyZuVQ7mxMoruGnqHRrOf+9gS5xUySH/QKf1C8RpA0QZDlGcJS6i7bhAk894x694EYZu37q\n' +
        'V2mWs/oPtWMFAscFUNReSUcHu2rWV546/spJLog7d891Hq/Dq5aVxOYJkZmwLnFOc2Rz1qmz5s+\n' +
        'ExlXaDoGphVVYgq4Lhm6HQ4zKDCqo8oIPWGLCG437mTU1axmMPLNcDOEXqSfHLOhiOPgDS9YrYJ\n' +
        'EPAfiEfE3tR7SfqLMy9kwNmDM86EtPmoZcYEDHhz3oaVwT07+wwRH63cTGdPOlg8FusfBqFh8Ob\n' +
        '2molhY6JdLeH1jc42rs0/GNWIH/kcm+LVAWqLRvax5nVCBMreKj1EfvsBADfUdXoIotRs1wqixO\n' +
        'D1p1PgRNJKBP4t7j2OXaij7FyKz6LU8dC6FcWvGAxkBeB5Lgo8GG/AaSMWwJY6eRTV8wBCsj9TL\n' +
        'M9+dhvZdQSvBGlstWgLLk1bPuAlNabOdnDmJa+IavKafaiP8LYCrfKaBZ2/ogC+aEvipEEOCk0J\n' +
        'h+A/PBcwl3Z+oPBzKNVvox0Cvp6rCUjuRVaH/TcoijASQ9DK0c8Kz2bc1BzAUJYGag1JngHsPbw\n' +
        'T41oifOVevJeVfl8Fe5M7UPGUyNm7Khu/l8pg25rO7n0MfIjgnyFVOZ/2aeZFy4ww/Ix1GLRLkS\n' +
        '6VvlY2Bh6yhn0mFMIJPWZsUHVfbxuPpD2tPPufULiIXx/r/09HBlJp420GggTVIiMh9zXrek0vz\n' +
        'Mb/dfAnqX2msIF//R8LjsVBu9SRdDlqbJW3vviX1rw1XRT8Bpg5ieSWz8uVt7dzYzzsMwi8YwaA\n' +
        'FynwFHzi1aymP1gAyklubtcw8A="}';
      const backupKey = '{"iv":"lbXgY5IYb9z3gwuYsD6oJA==","v":1,"iter":10000,"ks":256,"ts":64,"mode"\n' +
        ':"ccm","adata":"","cipher":"aes","salt":"Wg9AcOhVCWQ=","ct":"YeJOJDQ6f/rc0D\n' +
        'nlsXyLYc6qhTITyEkZyFmt4X7TFMoG4otdVdx/wh+ieC/lssAgooqwyiW056QGFNCTIMbEI/zSm\n' +
        'rS362hQx9QK49Eadkc5pO2Qfm/EXlYAAi/hFe2q8tk4IU+CAowW7QcyJ5NMIb+J2ImqGKxgROC9\n' +
        '4M4/ZxXTtbkalEVtwAF0Pyui8O0p+JHA/Q1D+9yPl3SfXu6D/GYV+RcmMtgae+wQYuIdx7fxGQk\n' +
        'EqMy9NfewKK/T+2SLpqYwED3C6OtMOM2URkPpU72KmRUzZllxk1/oLFVcHycLTd68qyfQr7QN2f\n' +
        '8pKKvq7VdbLBS+VIcTbSFpO6WPJrEt/oUqQ8E3FLCQ7sAkZe6NNzyREJ5Ci/xCvnEAmeJz04kiR\n' +
        'qE4XGYpqObUhMHjfl80T2fxE66xdgCrbUfhPsQhmmJly8q1gFln3I6UJ+szXN4F0WAqx2SupHFy\n' +
        '/JcGhyquq7b/+AXth3fFGdI3xL5x9ygMyCndUyk6bie8DWgtc6UW/a5Hz7FDNh7r2SujF0gHDut\n' +
        'yI7ff9qRfSTqf75YI3vkhqJp3O+LNiQpuTqpwPCTNl92FnAtcdEAw3V6QQXEe+rPlUeJbym1Qa/\n' +
        'cNHT0HGxd9/Yqd635CjhH2xUK4I2NyTaRvoNQh9PLUMVL/UqHRbL+AOTn7deVGRMBTf2GtfJcnV\n' +
        'cvtopuik+MlhceDu2SIwIgWbvXApV6drBnX8W7HPczcIi5O/IH2XawXIvSV6JsVxXeYY/KUsfih\n' +
        '+RK4Qs5x8kZHyjl3vuFBEL4tWaKyc3A1zt375+3PUsDUMR+wyP3ANzXsgxpvzOVX/KFP709Mp0v\n' +
        'YJyctc/N1XD/RZ2xj6bha6ybsFUiNfT3v83+dKSMLUKzDe0IDqoC/XgYpo89z0zyFG4jpnVqUHz\n' +
        'hxrDtsDch1fFf/4B4xm8uGfDNcc0f5O+8eAzzmy/Kat79i9V1xCAE8gn7mAZILkzLnSbD1JyXaG\n' +
        '5NK0trXhDQqFp7Gt6zYv6aG"}';
      const bitgoKey = '8699d2e05d60a3f7ab733a74ccf707f3407494b60f4253616187f5262e20737519a1763de0b\n' +
        'cc4d165a7fa0e4dde67a1426ec4cc9fcd0820d749e6589dcfa08e';
      const unsignedRecoveryTransaction = await basecoin.recover({
        userKey,
        backupKey,
        bitgoKey,
        recoveryDestination: 'abhay-near.testnet',
        walletPassphrase: 'Ghghjkg!455544llll'
      });
    });
  });
});


