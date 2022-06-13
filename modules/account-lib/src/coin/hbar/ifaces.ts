import { KeyPair } from '.';

export interface TxData {
  id: string;
  hash?: string;
  from: string;
  data: string;
  fee: number;
  startTime: string;
  validDuration: string;
  node: string;
  memo?: string;
  to?: string;
  amount?: string;
  tokenName?: string;
}

export interface HederaNode {
  nodeId: string;
}

export interface SignatureData {
  signature: string;
  keyPair: KeyPair;
}

export interface AddressDetails {
  address: string;
  memoId?: string;
}
