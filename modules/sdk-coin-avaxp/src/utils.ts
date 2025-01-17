import { isValidXpub, NotImplementedError, BaseUtils } from '@bitgo/sdk-core';
import { BinTools, Buffer } from 'avalanche';
import { NodeIDStringToBuffer } from 'avalanche/dist/utils';
import { ec } from 'elliptic';
import { BaseTx, SelectCredentialClass, Tx, UnsignedTx } from 'avalanche/dist/apis/platformvm';
import { Credential } from 'avalanche/dist/common/credentials';

export class Utils implements BaseUtils {
  private binTools = BinTools.getInstance();
  public cb58Decode = this.binTools.cb58Decode;
  public cb58Encode = this.binTools.cb58Encode;
  public stringToBuffer = this.binTools.stringToBuffer;
  public bufferToString = this.binTools.bufferToString;
  public NodeIDStringToBuffer = NodeIDStringToBuffer;
  public addressToString = this.binTools.addressToString;

  public includeIn(walletAddresses: string[], otxoOutputAddresses: string[]): boolean {
    return walletAddresses.map((a) => otxoOutputAddresses.includes(a)).reduce((a, b) => a && b, true);
  }
  /** @inheritdoc */
  isValidAddress(address: string): boolean {
    throw new NotImplementedError('isValidAddress not implemented');
  }

  /** @inheritdoc */
  isValidBlockId(hash: string): boolean {
    throw new NotImplementedError('isValidBlockId not implemented');
  }

  /**
   * Checks if the string is a valid protocol public key or
   * extended public key.
   *
   * @param {string} pub - the  public key to be validated
   * @returns {boolean} - the validation result
   */
  isValidPublicKey(pub: string): boolean {
    if (isValidXpub(pub)) return true;

    if (pub.length !== 66 && pub.length !== 130) return false;

    const firstByte = pub.slice(0, 2);

    // uncompressed public key
    if (pub.length === 130 && firstByte !== '04') return false;

    // compressed public key
    if (pub.length === 66 && firstByte !== '02' && firstByte !== '03') return false;

    if (!this.allHexChars(pub)) return false;

    // validate the public key
    const secp256k1 = new ec('secp256k1');
    try {
      const keyPair = secp256k1.keyFromPublic(Buffer.from(pub, 'hex'));
      const { result } = keyPair.validate();
      return result;
    } catch (e) {
      return false;
    }
  }
  public parseAddress = (pub: string): Buffer => this.binTools.parseAddress(pub, 'P');

  /**
   * Returns whether or not the string is a valid protocol private key, or extended
   * private key.
   *
   * The protocol key format is described in the @stacks/transactions npm package, in the
   * createStacksPrivateKey function:
   * https://github.com/blockstack/stacks.js/blob/master/packages/transactions/src/keys.ts#L125
   *
   * @param {string} prv - the private key (or extended private key) to be validated
   * @returns {boolean} - the validation result
   */
  isValidPrivateKey(prv: string): boolean {
    // if (isValidXprv(prv)) return true;

    if (prv.length !== 64 && prv.length !== 66) return false;

    if (prv.length === 66 && prv.slice(64) !== '01') return false;

    return this.allHexChars(prv);
  }

  /**
   * Returns whether or not the string is a composed of hex chars only
   *
   * @param {string} maybe - the  string to be validated
   * @returns {boolean} - the validation result
   */
  allHexChars(maybe: string): boolean {
    return /^([0-9a-f])+$/i.test(maybe);
  }

  /** @inheritdoc */
  isValidSignature(signature: string): boolean {
    throw new NotImplementedError('isValidSignature not implemented');
  }

  /** @inheritdoc */
  isValidTransactionId(txId: string): boolean {
    throw new NotImplementedError('isValidTransactionId not implemented');
  }

  getCredentials(tx: BaseTx): Credential[] {
    return tx.getIns().map((ins) => SelectCredentialClass(ins.getInput().getCredentialID()));
  }

  from(raw: string): Tx {
    const tx = new Tx();
    try {
      tx.fromString(raw);
      return tx;
    } catch (err) {
      const utx = new UnsignedTx();
      utx.fromBuffer(utils.cb58Decode(raw));
      return new Tx(utx, []);
    }
  }
}

const utils = new Utils();

export default utils;
