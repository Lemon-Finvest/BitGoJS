/**
 * @prettier
 */

import BigNumber from 'bignumber.js';
import * as accountLib from '@bitgo/account-lib';
import * as _ from 'lodash';
import * as base58 from 'bs58';
import { BaseCoin as StaticsBaseCoin, CoinFamily, coins } from '@bitgo/statics';
import {
  BaseCoin,
  BitGoBase,
  BaseTransaction,
  KeyPair,
  MethodNotImplementedError,
  ParsedTransaction as BaseParsedTransaction,
  ParseTransactionOptions as BaseParseTransactionOptions,
  SignedTransaction,
  SignTransactionOptions as BaseSignTransactionOptions,
  TransactionExplanation,
  VerifyAddressOptions,
  VerifyTransactionOptions,
  Ed25519BIP32,
  Eddsa,
  PublicKey,
} from '@bitgo/sdk-core';
import * as nearAPI from 'near-api-js';

require('dotenv').config();
import { SigningMaterial } from '../../../../sdk-core/src';
import { NearGasConfigs } from '../../config';

export interface SignTransactionOptions extends BaseSignTransactionOptions {
  txPrebuild: TransactionPrebuild;
  prv: string;
}

export interface TransactionPrebuild {
  txHex: string;
  key: string;
  blockHash: string;
  nonce: number;
}

export interface ExplainTransactionOptions {
  txPrebuild: TransactionPrebuild;
  publicKey: string;
  feeInfo: {
    fee: string;
  };
}

export interface VerifiedTransactionParameters {
  txHex: string;
  prv: string;
  signer: string;
}

export interface NearParseTransactionOptions extends BaseParseTransactionOptions {
  txPrebuild: TransactionPrebuild;
  publicKey: string;
  feeInfo: {
    fee: string;
  };
}

interface TransactionOutput {
  address: string;
  amount: string;
}

type TransactionInput = TransactionOutput;

export interface NearParsedTransaction extends BaseParsedTransaction {
  // total assets being moved, including fees
  inputs: TransactionInput[];

  // where assets are moved to
  outputs: TransactionOutput[];
}

export type NearTransactionExplanation = TransactionExplanation;

const nearUtils = accountLib.Near.Utils.default;

export class Near extends BaseCoin {
  protected readonly _staticsCoin: Readonly<StaticsBaseCoin>;
  constructor(bitgo: BitGoBase, staticsCoin?: Readonly<StaticsBaseCoin>) {
    super(bitgo);

    if (!staticsCoin) {
      throw new Error('missing required constructor parameter staticsCoin');
    }

    this._staticsCoin = staticsCoin;
  }

  static createInstance(bitgo: BitGoBase, staticsCoin?: Readonly<StaticsBaseCoin>): BaseCoin {
    return new Near(bitgo, staticsCoin);
  }

  allowsAccountConsolidations(): boolean {
    return true;
  }

  /**
   * Flag indicating if this coin supports TSS wallets.
   * @returns {boolean} True if TSS Wallets can be created for this coin
   */
  supportsTss(): boolean {
    return true;
  }

  supportsStaking(): boolean {
    return true;
  }

  getChain(): string {
    return this._staticsCoin.name;
  }

  getBaseChain(): string {
    return this.getChain();
  }

  getFamily(): CoinFamily {
    return this._staticsCoin.family;
  }

  getFullName(): string {
    return this._staticsCoin.fullName;
  }

  getBaseFactor(): any {
    return Math.pow(10, this._staticsCoin.decimalPlaces);
  }

  /**
   * Flag for sending value of 0
   * @returns {boolean} True if okay to send 0 value, false otherwise
   */
  valuelessTransferAllowed(): boolean {
    return false;
  }

  /**
   * Generate ed25519 key pair
   *
   * @param seed
   * @returns {Object} object with generated pub, prv
   */
  generateKeyPair(seed?: Buffer): KeyPair {
    const keyPair = seed ? new accountLib.Near.KeyPair({ seed }) : new accountLib.Near.KeyPair();
    const keys = keyPair.getKeys();
    if (!keys.prv) {
      throw new Error('Missing prv in key generation.');
    }
    return {
      pub: keys.pub,
      prv: keys.prv,
    };
  }

  /**
   * Return boolean indicating whether input is valid public key for the coin.
   *
   * @param {String} pub the pub to be checked
   * @returns {Boolean} is it valid?
   */
  isValidPub(pub: string): boolean {
    return nearUtils.isValidPublicKey(pub);
  }

  /**
   * Return boolean indicating whether the supplied private key is a valid near private key
   *
   * @param {String} prv the prv to be checked
   * @returns {Boolean} is it valid?
   */
  isValidPrv(prv: string): boolean {
    return nearUtils.isValidPrivateKey(prv);
  }

  /**
   * Return boolean indicating whether input is valid public key for the coin
   *
   * @param {String} address the pub to be checked
   * @returns {Boolean} is it valid?
   */
  isValidAddress(address: string): boolean {
    return nearUtils.isValidAddress(address);
  }

  /** @inheritDoc */
  async signMessage(key: KeyPair, message: string | Buffer): Promise<Buffer> {
    const nearKeypair = new accountLib.Near.KeyPair({ prv: key.prv });
    if (Buffer.isBuffer(message)) {
      message = base58.encode(message);
    }

    return Buffer.from(nearKeypair.signMessage(message));
  }

  /**
   * Explain/parse transaction
   * @param params
   */
  async explainTransaction(params: ExplainTransactionOptions): Promise<NearTransactionExplanation> {
    const factory = accountLib.register(this.getChain(), accountLib.Near.TransactionBuilderFactory);
    let rebuiltTransaction: BaseTransaction;
    const txRaw = params.txPrebuild.txHex;

    try {
      const transactionBuilder = factory.from(txRaw);
      rebuiltTransaction = await transactionBuilder.build();
    } catch {
      throw new Error('Invalid transaction');
    }

    return rebuiltTransaction.explainTransaction();
  }

  verifySignTransactionParams(params: SignTransactionOptions): VerifiedTransactionParameters {
    const prv = params.prv;

    const txHex = params.txPrebuild.txHex;

    if (_.isUndefined(txHex)) {
      throw new Error('missing txPrebuild parameter');
    }

    if (!_.isString(txHex)) {
      throw new Error(`txPrebuild must be an object, got type ${typeof txHex}`);
    }

    if (_.isUndefined(prv)) {
      throw new Error('missing prv parameter to sign transaction');
    }

    if (!_.isString(prv)) {
      throw new Error(`prv must be a string, got type ${typeof prv}`);
    }

    if (!_.has(params.txPrebuild, 'key')) {
      throw new Error('missing public key parameter to sign transaction');
    }

    // if we are receiving addresses do not try to convert them
    const signer = !nearUtils.isValidAddress(params.txPrebuild.key)
      ? new accountLib.Near.KeyPair({ pub: params.txPrebuild.key }).getAddress()
      : params.txPrebuild.key;
    return { txHex, prv, signer };
  }

  /**
   * Assemble keychain and half-sign prebuilt transaction
   *
   * @param params
   * @param params.txPrebuild {TransactionPrebuild} prebuild object returned by platform
   * @param params.prv {String} user prv
   * @param callback
   * @returns {Bluebird<SignedTransaction>}
   */
  async signTransaction(params: SignTransactionOptions): Promise<SignedTransaction> {
    const factory = accountLib.register(this.getChain(), accountLib.Near.TransactionBuilderFactory);
    const txBuilder = factory.from(params.txPrebuild.txHex);
    txBuilder.sign({ key: params.prv });
    const transaction: BaseTransaction = await txBuilder.build();

    if (!transaction) {
      throw new Error('Invalid transaction');
    }

    const serializedTx = (transaction as BaseTransaction).toBroadcastFormat();

    return {
      txHex: serializedTx,
    } as any;
  }

  async signWithTSS(userSigningMaterial, backupSigningMaterial, path = 'm/0', transaction) {
    const hdTree = await Ed25519BIP32.initialize();
    const MPC = await Eddsa.initialize(hdTree);
    const user_combine = MPC.keyCombine(userSigningMaterial.uShare, [
      userSigningMaterial.bitgoYShare,
      userSigningMaterial.backupYShare,
    ]);
    const backup_combine = MPC.keyCombine(backupSigningMaterial.uShare, [
      backupSigningMaterial.bitgoYShare,
      backupSigningMaterial.userYShare,
    ]);

    // Party A derives subkey P share and new Y shares.
    const user_subkey = MPC.keyDerive(
      userSigningMaterial.uShare,
      [userSigningMaterial.bitgoYShare, userSigningMaterial.backupYShare],
      path
    );

    // Party B calculates new P share using party A's subkey Y shares.
    const backup_subkey = MPC.keyCombine(backupSigningMaterial.uShare, [
      user_subkey.yShares[2],
      backupSigningMaterial.bitgoYShare,
    ]);

    const message_buffer = Buffer.from(transaction.signablePayload, 'hex');
    // Signing with A and B using subkey P shares.
    const user_sign_share = MPC.signShare(message_buffer, user_subkey.pShare, [user_combine.jShares[2]]);
    const backup_sign_share = MPC.signShare(message_buffer, backup_subkey.pShare, [backup_combine.jShares[1]]);
    const user_sign = MPC.sign(
      message_buffer,
      user_sign_share.xShare,
      [backup_sign_share.rShares[1]],
      [userSigningMaterial.bitgoYShare]
    );
    const backup_sign = MPC.sign(
      message_buffer,
      backup_sign_share.xShare,
      [user_sign_share.rShares[2]],
      [backupSigningMaterial.bitgoYShare]
    );
    const signature = MPC.signCombine([user_sign, backup_sign]);
    const result = MPC.verify(message_buffer, signature);
    result.should.equal(true);
    const rawSignature = Buffer.concat([Buffer.from(signature.R, 'hex'), Buffer.from(signature.sigma, 'hex')]);
    return rawSignature;
  }

  /**
   * Builds a funds recovery transaction without BitGo
   * @param params
   */
  async recover(params: any): Promise<any> {
    if (_.isUndefined(params.userKey)) {
      throw new Error('missing userKey');
    }

    if (_.isUndefined(params.backupKey)) {
      throw new Error('missing backupKey');
    }

    if (_.isUndefined(params.bitgoKey)) {
      throw new Error('missing backupKey');
    }

    if (_.isUndefined(params.walletPassphrase) && !params.userKey.startsWith('xpub')) {
      throw new Error('missing wallet passphrase');
    }

    if (_.isUndefined(params.recoveryDestination) || !this.isValidAddress(params.recoveryDestination)) {
      throw new Error('invalid recoveryDestination');
    }
    const keyStore = new nearAPI.keyStores.InMemoryKeyStore();
    const config = {
      keyStore,
      networkId: 'testnet',
      nodeUrl: 'https://rpc.testnet.near.org',
    };

    // Clean up whitespace from entered values
    const userKey = params.userKey.replace(/\s/g, '');
    const backupKey = params.backupKey.replace(/\s/g, '');
    const bitgoKey = params.bitgoKey.replace(/\s/g, '');

    // Decrypt private keys from KeyCard values
    let userPrv;
    if (!userKey.startsWith('xpub') && !userKey.startsWith('xprv')) {
      try {
        userPrv = this.bitgo.decrypt({
          input: userKey,
          password: params.walletPassphrase,
        });
      } catch (e) {
        throw new Error(`Error decrypting user keychain: ${e.message}`);
      }
    }
    const userSigningMaterial = JSON.parse(userPrv) as SigningMaterial;

    let backupPrv;
    try {
      backupPrv = this.bitgo.decrypt({
        input: backupKey,
        password: params.walletPassphrase,
      });
    } catch (e) {
      throw new Error(`Error decrypting backup keychain: ${e.message}`);
    }
    const backupSigningMaterial = JSON.parse(backupPrv) as SigningMaterial;
    // TODO: use common implementation of deriveUnhardened
    const publicKey = await this.deriveUnhardened(bitgoKey, `m/0`);
    const bs58EncodeedPublicKey = nearAPI.utils.serialize.base_encode(new Uint8Array(Buffer.from(publicKey, 'hex')));

    const provider = new nearAPI.providers.JsonRpcProvider(`https://rpc.testnet.near.org`);
    const accessKey = await provider.query(`access_key/${publicKey}/${bs58EncodeedPublicKey}`, '');

    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const nonce = ++accessKey.nonce;
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const near = await nearAPI.connect(config);
    const account = await near.account(publicKey);
    const balance = await account.getAccountBalance();
    const gasPrice = await near.connection.provider.gasPrice(accessKey.block_hash);
    const gasPriceFirstBlock = new BigNumber(gasPrice.gas_price);
    const gasPriceSecondBlock = gasPriceFirstBlock.multipliedBy(1.05);
    console.log('balance: ', balance);
    console.log('gas: ', gasPriceFirstBlock);
    const { transfer_cost, action_receipt_creation_config } = NearGasConfigs;
    const totalGasRequired = transfer_cost.send_sir
      .plus(action_receipt_creation_config.send_sir)
      .multipliedBy(gasPriceFirstBlock)
      .plus(transfer_cost.execution.plus(action_receipt_creation_config.execution).multipliedBy(gasPriceSecondBlock));
    // adding some padding to make sure the gas doesn't go below required gas by network
    const totalGasWithPadding = totalGasRequired.multipliedBy(1.5);
    console.log('totalGas: ', totalGasWithPadding);
    const accontBalance = new BigNumber(balance.available);
    const netAmount = accontBalance.minus(totalGasWithPadding).toFixed();
    const factory = accountLib.register('tnear', accountLib.Near.TransactionBuilderFactory);

    const txBuilder = factory
      .getTransferBuilder()
      .sender(publicKey, publicKey)
      .nonce(nonce)
      .receiverId(params.recoveryDestination)
      .recentBlockHash(accessKey.block_hash)
      .amount(netAmount);
    const unsignedTransaction = await txBuilder.build();
    const serializedTxHex = Buffer.from(unsignedTransaction.toBroadcastFormat(), 'base64').toString('hex');

    // add signature
    const txBuilder2 = factory.from(Buffer.from(serializedTxHex, 'hex').toString('base64'));
    const signatureHex = await this.signWithTSS(userSigningMaterial, backupSigningMaterial, 'm/0', unsignedTransaction);
    const publicKeyObj = { pub: publicKey };
    txBuilder2.addSignature(publicKeyObj as PublicKey, signatureHex);
    const signedTransaction = await txBuilder2.build();
    const serializedTx = signedTransaction.toBroadcastFormat();

    console.log('send', serializedTx);
    const result = await provider.sendJsonRpc('broadcast_tx_commit', [serializedTx]);
    console.log(result);

    return signedTransaction;
  }

  async deriveUnhardened(commonKeychain: string, path: string): Promise<string> {
    await Ed25519BIP32.initialize();
    await Eddsa.initialize();
    const mpc = new Eddsa(new Ed25519BIP32());
    return mpc.deriveUnhardened(commonKeychain, path).slice(0, 64);
  }

  async parseTransaction(params: NearParseTransactionOptions): Promise<NearParsedTransaction> {
    const transactionExplanation = await this.explainTransaction({
      txPrebuild: params.txPrebuild,
      publicKey: params.publicKey,
      feeInfo: params.feeInfo,
    });

    if (!transactionExplanation) {
      throw new Error('Invalid transaction');
    }

    const nearTransaction = transactionExplanation as NearTransactionExplanation;
    if (nearTransaction.outputs.length <= 0) {
      return {
        inputs: [],
        outputs: [],
      };
    }

    const senderAddress = nearTransaction.outputs[0].address;
    const feeAmount = new BigNumber(nearTransaction.fee.fee === '' ? '0' : nearTransaction.fee.fee);

    // assume 1 sender, who is also the fee payer
    const inputs = [
      {
        address: senderAddress,
        amount: new BigNumber(nearTransaction.outputAmount).plus(feeAmount).toFixed(),
      },
    ];

    const outputs: TransactionOutput[] = nearTransaction.outputs.map((output) => {
      return {
        address: output.address,
        amount: new BigNumber(output.amount).toFixed(),
      };
    });

    return {
      inputs,
      outputs,
    };
  }

  isWalletAddress(params: VerifyAddressOptions): boolean {
    throw new MethodNotImplementedError();
  }

  async verifyTransaction(params: VerifyTransactionOptions): Promise<boolean> {
    let totalAmount = new BigNumber(0);
    const coinConfig = coins.get(this.getChain());
    const { txPrebuild: txPrebuild, txParams: txParams } = params;
    const transaction = new accountLib.Near.Transaction(coinConfig);
    const rawTx = txPrebuild.txHex;
    if (!rawTx) {
      throw new Error('missing required tx prebuild property txHex');
    }

    transaction.fromRawTransaction(rawTx);
    const explainedTx = transaction.explainTransaction();

    // users do not input recipients for consolidation requests as they are generated by the server
    if (txParams.recipients !== undefined) {
      const filteredRecipients = txParams.recipients?.map((recipient) => _.pick(recipient, ['address', 'amount']));
      const filteredOutputs = explainedTx.outputs.map((output) => _.pick(output, ['address', 'amount']));

      if (!_.isEqual(filteredOutputs, filteredRecipients)) {
        throw new Error('Tx outputs does not match with expected txParams recipients');
      }
      for (const recipients of txParams.recipients) {
        totalAmount = totalAmount.plus(recipients.amount);
      }
      if (!totalAmount.isEqualTo(explainedTx.outputAmount)) {
        throw new Error('Tx total amount does not match with expected total amount field');
      }
    }
    return true;
  }
}
