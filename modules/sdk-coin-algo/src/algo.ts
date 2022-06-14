import {
  BaseCoin,
  BitGoBase,
  KeyPair,
  ParsedTransaction,
  ParseTransactionOptions,
  SignedTransaction,
  SignTransactionOptions,
  VerifyAddressOptions,
  VerifyTransactionOptions,
} from '@bitgo/sdk-core';

export class Algo extends BaseCoin {
  verifyTransaction(params: VerifyTransactionOptions): Promise<boolean> {
    throw new Error('Method not implemented.');
  }
  isWalletAddress(params: VerifyAddressOptions): boolean {
    throw new Error('Method not implemented.');
  }
  parseTransaction(params: ParseTransactionOptions): Promise<ParsedTransaction> {
    throw new Error('Method not implemented.');
  }
  generateKeyPair(seed?: Buffer | undefined): KeyPair {
    throw new Error('Method not implemented.');
  }
  isValidPub(pub: string): boolean {
    throw new Error('Method not implemented.');
  }
  isValidAddress(address: string): boolean {
    throw new Error('Method not implemented.');
  }
  signTransaction(params: SignTransactionOptions): Promise<SignedTransaction> {
    throw new Error('Method not implemented.');
  }
  protected constructor(bitgo: BitGoBase) {
    super(bitgo);
  }

  static createInstance(bitgo: BitGoBase): BaseCoin {
    return new Algo(bitgo);
  }

  /**
   * Factor between the coin's base unit and its smallest subdivison
   */
  public getBaseFactor(): number {
    return 1e6;
  }

  public getChain(): string {
    return 'algo';
  }

  public getFamily(): string {
    return 'algo';
  }

  public getFullName(): string {
    return 'Algorand';
  }
}
