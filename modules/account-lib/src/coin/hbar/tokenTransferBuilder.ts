import { BaseCoin as CoinConfig } from '@bitgo/statics';
import * as Long from 'long';
import { TokenId } from '@hashgraph/sdk';
import { proto } from '../../../resources/hbar/protobuf/hedera';
import { BuildTransactionError, InvalidParameterValueError } from '@bitgo/sdk-core';
import { TransferBuilder } from './transferBuilder';
import { Transaction } from './transaction';
import { getHbarTokenFromTokenName, isValidToken, stringifyAccountId, stringifyTokenId } from './utils';

export class TokenTransferBuilder extends TransferBuilder {
  private _tokenId: string;

  constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
  }

  /** @inheritdoc */
  protected async buildImplementation(): Promise<Transaction> {
    this._txBodyData.tokenTransfers = [this.buildTokenTransferData()]; // set to list by the contract
    return await super.buildImplementation(true);
  }

  private buildTokenTransferData(): proto.ITokenTransferList {
    return {
      token: this.buildTokenId(this._tokenId),
      transfers: [
        { accountID: this.buildAccountData(this._source.address), amount: Long.fromString(this._amount).negate() }, // sender
        { accountID: this.buildAccountData(this._toAddress), amount: Long.fromString(this._amount) }, // recipient
      ],
    };
  }

  private buildTokenId(tokenId: string): proto.TokenID {
    const tokenData = TokenId.fromString(tokenId);
    return new proto.TokenID({
      tokenNum: tokenData.num,
      realmNum: tokenData.realm,
      shardNum: tokenData.shard,
    });
  }

  /** @inheritdoc */
  initBuilder(tx: Transaction): void {
    super.initBuilder(tx, true);
    const transferData = tx.txBody.cryptoTransfer;
    if (transferData && transferData.tokenTransfers && transferData.tokenTransfers.length > 0) {
      this.initTokenTransfers(transferData.tokenTransfers);
    }
  }

  /**
   * Initialize the transfer specific data, getting the recipient account
   * represented by the element with a positive amount on the transfer element.
   * The negative amount represents the source account so it's ignored.
   *
   * @param {proto.IAccountAmount[]} transfers array of objects which contains accountID and transferred amount
   */
  protected initTokenTransfers(tokenTransfers: proto.ITokenTransferList[]): void {
    const tokenTransfer = tokenTransfers[0];
    if (!tokenTransfer.token) {
      throw new InvalidParameterValueError('missing token id');
    }
    if (!tokenTransfer.transfers) {
      throw new InvalidParameterValueError('missing transfer data');
    }
    tokenTransfer.transfers.forEach((transferData) => {
      const amount = Long.fromValue(transferData.amount!);
      if (amount.isPositive()) {
        this.to(stringifyAccountId(transferData.accountID!));
        this.amount(amount.toString());
        const tokenId = stringifyTokenId(tokenTransfer.token!);
        if (!isValidToken(tokenId, this._coinConfig.network)) {
          throw new InvalidParameterValueError('Invalid token id');
        }
        this._tokenId = tokenId;
      }
    });
  }

  // region Transfer fields
  /**
   * Set the token id to be of the transaction from token name
   *
   * @param {string} tokenName the token name for the token
   * @returns {TransferBuilder} the builder with the new parameter set
   */
  tokenName(tokenName: string): this {
    const tokenId = getHbarTokenFromTokenName(tokenName)?.tokenId;
    if (!tokenId) {
      throw new InvalidParameterValueError('Invalid token name');
    }
    this._tokenId = tokenId;
    return this;
  }

  // region Validators
  validateMandatoryFields(): void {
    if (this._tokenId === undefined) {
      throw new BuildTransactionError('Invalid transaction: missing token id');
    }
    super.validateMandatoryFields();
  }
  // endregion
}
