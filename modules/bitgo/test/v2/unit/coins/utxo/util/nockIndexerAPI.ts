/**
 * @prettier
 */
import * as nock from 'nock';
import * as utxolib from '@bitgo/utxo-lib';
import { AbstractUtxoCoin, ExplorerTxInfo } from '@bitgo/abstract-utxo';
import { nockBitGo } from './nockBitGo';

type Unspent = utxolib.bitgo.Unspent;

export function nockBitGoPublicTransaction(
  coin: AbstractUtxoCoin,
  tx: utxolib.bitgo.UtxoTransaction,
  unspents: Unspent[]
): nock.Scope {
  const payload: ExplorerTxInfo = {
    input: unspents.map((u) => ({ address: u.address })),
    outputs: tx.outs.map((o) => ({ address: utxolib.address.fromOutputScript(o.script, coin.network) })),
  };
  return nockBitGo().get(`/api/v2/${coin.getChain()}/public/tx/${tx.getId()}`).reply(200, payload);
}

export function nockBitGoPublicAddressUnspents(
  coin: AbstractUtxoCoin,
  txid: string,
  address: string,
  outputs: utxolib.TxOutput[]
): nock.Scope {
  const payload: Unspent[] = outputs.map(
    (o, vout: number): Unspent => ({
      id: `${txid}:${vout}`,
      address: utxolib.address.fromOutputScript(o.script, coin.network),
      value: o.value,
    })
  );
  return nockBitGo().get(`/api/v2/${coin.getChain()}/public/addressUnspents/${address}`).reply(200, payload);
}
