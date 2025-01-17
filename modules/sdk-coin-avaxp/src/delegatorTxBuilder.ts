import { BaseAddress, BuildTransactionError, TransactionType } from '@bitgo/sdk-core';
import { AvalancheNetwork, BaseCoin as CoinConfig } from '@bitgo/statics';
import { TransactionBuilder } from './transactionBuilder';
import {
  AddDelegatorTx,
  BaseTx,
  ParseableOutput,
  SECPOwnerOutput,
  SECPTransferInput,
  SECPTransferOutput,
  TransferableInput,
  TransferableOutput,
} from 'avalanche/dist/apis/platformvm';
import { BN } from 'avalanche';
import { DecodedUtxoObj } from './iface';
import utils from './utils';

export class DelegatorTxBuilder extends TransactionBuilder {
  protected _nodeID: string;
  protected _startTime: BN;
  protected _endTime: BN;
  protected _stakeAmount: BN;
  protected _rewardAddress: BaseAddress;

  /**
   *
   * @param coinConfig
   */
  constructor(coinConfig: Readonly<CoinConfig>) {
    super(coinConfig);
    const network = coinConfig.network as AvalancheNetwork;
    this._stakeAmount = new BN(network.minStake.toString());
  }

  /**
   * get transaction type
   * @protected
   */
  protected get transactionType(): TransactionType {
    return TransactionType.addDelegator;
  }

  /**
   *
   * @param nodeID
   */
  nodeID(value: string): this {
    this.validateNodeID(value);
    this._nodeID = value;
    return this;
  }

  /**
   *
   * @param startTime
   */
  startTime(value: string | number): this {
    this._startTime = new BN(value);
    return this;
  }

  /**
   *
   * @param endTime
   */
  endTime(value: string | number): this {
    this._endTime = new BN(value);
    return this;
  }

  /**
   *
   * @param value
   */
  stakeAmount(value: BN | string): this {
    const valueBN = BN.isBN(value) ? value : new BN(value);
    this.validateStakeAmount(valueBN);
    this._stakeAmount = valueBN;
    return this;
  }

  /**
   * Set the transaction source
   *
   * @param {BaseAddress} address The source account
   * @returns {TransactionBuilder} This transaction builder
   */
  rewardAddress(address: BaseAddress): this {
    this.validateAddress(address);
    this._rewardAddress = address;
    return this;
  }

  /**
   * region Validators
   */

  /**
   * validates a correct NodeID is used
   * @param nodeID
   */
  validateNodeID(nodeID: string): void {
    if (!nodeID) {
      throw new BuildTransactionError('Invalid transaction: missing nodeID');
    }
    if (nodeID.slice(0, 6) !== 'NodeID') {
      throw new BuildTransactionError('Invalid transaction: invalid NodeID tag');
    }
    if (nodeID.length !== 40) {
      throw new BuildTransactionError('Invalid transaction: NodeID has incorrect length');
    }
  }
  /**
   *
   *   protected _startTime: Date;
   *   protected _endTime: Date;
   *   2 weeks = 1209600
   *   1 year = 31556926
   *   unix time stamp based off seconds
   */
  validateStakeDuration(startTime: BN, endTime: BN): void {
    if (endTime < startTime) {
      throw new BuildTransactionError('End date cannot be less than start date');
    }
    if (startTime.add(new BN(this.transaction._network.minStakeDuration)).gt(endTime)) {
      throw new BuildTransactionError('End date must be greater than or equal to two weeks');
    }
    if (endTime.gt(startTime.add(new BN(this.transaction._network.maxStakeDuration)))) {
      throw new BuildTransactionError('End date must be less than or equal to one year');
    }
  }

  /**
   *
   * @param amount
   */
  validateStakeAmount(amount: BN): void {
    if (amount.lt(new BN(this.transaction._network.minStake.toString()))) {
      throw new BuildTransactionError('Minimum staking amount is 2,000 AVAX');
    }
  }

  // endregion

  initBuilder(tx?: AddDelegatorTx): this {
    if (!tx) return this;
    super.initBuilder(tx);
    this._nodeID = tx.getNodeIDString();
    this._startTime = tx.getStartTime();
    this._endTime = tx.getEndTime();
    this._stakeAmount = tx.getStakeAmount();
    this.transaction._utxos = this.recoverUtxos(tx.getIns());

    return this;
  }

  /**
   *
   * @protected
   */
  protected buildAvaxpTransaction(): BaseTx {
    const { inputs, outputs } = this.createInputOutput();
    return new AddDelegatorTx(
      this.transaction._networkID,
      this.transaction._blockchainID,
      outputs,
      inputs,
      this.transaction._memo,
      utils.NodeIDStringToBuffer(this._nodeID),
      this._startTime,
      this._endTime,
      this._stakeAmount,
      [this.stakeTransferOut()],
      this.rewardOwnersOutput()
    );
  }

  protected stakeTransferOut(): TransferableOutput {
    return new TransferableOutput(
      this.transaction._assetId,
      new SECPTransferOutput(
        this._stakeAmount,
        this.transaction._fromPubKeys,
        this.transaction._locktime,
        this.transaction._threshold
      )
    );
  }

  protected rewardOwnersOutput(): ParseableOutput {
    return new ParseableOutput(
      new SECPOwnerOutput(this.transaction._fromPubKeys, this.transaction._locktime, this.transaction._threshold)
    );
  }

  /**
   * Inputs can be controlled but outputs get reordered in transactions
   * In order to make sure that the mapping is always correct we create an addressIndx which matches to the appropiate
   * signatureIdx
   * @param inputs
   * @protected
   */
  protected recoverUtxos(inputs: TransferableInput[]): DecodedUtxoObj[] {
    return inputs.map((input) => {
      const secpInput: SECPTransferInput = input.getInput() as SECPTransferInput;
      // Order Addresses as output was defined.
      const addressesIndx: number[] = secpInput.getSigIdxs().map((s) => s.toBuffer().readUInt32BE(0));
      addressesIndx.push([0, 1, 2].filter((i) => !addressesIndx.includes(i))[0]);
      const addresses: string[] = [];
      // first index address is user
      addresses[addressesIndx[0]] = utils.addressToString(
        this.transaction._network.hrp,
        this.transaction._network.alias,
        this.transaction._fromPubKeys[0]
      );
      // second index address is bigto
      addresses[addressesIndx[1]] = utils.addressToString(
        this.transaction._network.hrp,
        this.transaction._network.alias,
        this.transaction._fromPubKeys[2]
      );
      // Unindex address is recovery
      addresses[addressesIndx[2]] = utils.addressToString(
        this.transaction._network.hrp,
        this.transaction._network.alias,
        this.transaction._fromPubKeys[1]
      );

      return {
        outputID: 7,
        outputidx: utils.cb58Encode(input.getOutputIdx()),
        txid: utils.cb58Encode(input.getTxID()),
        amount: secpInput.getAmount().toString(),
        threshold: this.transaction._threshold,
        addresses,
      };
    });
  }

  /**
   * Threshold must be 2 and since output always get reordered we want to make sure we can always add signatures in the correct location
   * To find the correct location for the signature, we use the ouput's addresses to create the signatureIdx in the order that we desire
   * 0: user key, 1: recovery key, 2: hsm key
   * @protected
   */
  protected createInputOutput(): { inputs: TransferableInput[]; outputs: TransferableOutput[] } {
    const inputs: TransferableInput[] = [];
    const outputs: TransferableOutput[] = [];
    const addresses = this.transaction._fromPubKeys.map((b) =>
      utils.addressToString(this.transaction._network.hrp, this.transaction._network.alias, b)
    );
    let total: BN = new BN(0);
    const totalTarget = this._stakeAmount.clone().add(this.transaction._txFee);
    this.transaction._utxos
      .filter(
        (output) => output.threshold === this.transaction._threshold && utils.includeIn(addresses, output.addresses)
      )
      .forEach((output, i) => {
        if (output.outputID === 7 && total.lte(totalTarget)) {
          const txidBuf = utils.cb58Decode(output.txid);
          const amt: BN = new BN(output.amount);
          const outputidx = utils.cb58Decode(output.outputidx);
          total = total.add(amt);

          const secpTransferInput = new SECPTransferInput(amt);
          if (this.recoverSigner) {
            secpTransferInput.addSignatureIdx(
              output.addresses.findIndex((a) => a === addresses[1]),
              this.transaction._fromPubKeys[1]
            );
          } else {
            secpTransferInput.addSignatureIdx(
              output.addresses.findIndex((a) => a === addresses[0]),
              this.transaction._fromPubKeys[0]
            );
          }
          secpTransferInput.addSignatureIdx(
            output.addresses.findIndex((a) => a === addresses[2]),
            this.transaction._fromPubKeys[2]
          );

          const input: TransferableInput = new TransferableInput(
            txidBuf,
            outputidx,
            this.transaction._assetId,
            secpTransferInput
          );
          inputs.push(input);
        }
      });
    if (total.lt(totalTarget)) {
      throw new BuildTransactionError(`Utxo outputs get ${total.toString()} and ${totalTarget.toString()} is required`);
    }
    outputs.push(
      new TransferableOutput(
        this.transaction._assetId,
        new SECPTransferOutput(
          total.sub(totalTarget),
          this.transaction._fromPubKeys,
          this.transaction._locktime,
          this.transaction._threshold
        )
      )
    );

    return { inputs, outputs };
  }
}
