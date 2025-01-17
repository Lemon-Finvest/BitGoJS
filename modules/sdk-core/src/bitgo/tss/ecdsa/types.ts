import { ECDSA } from './../../../account-lib/mpc/tss';

// NShare that has been encrypted and signed via GPG
export type EncryptedNShare = {
  i: number;
  j: number;
  n: string;
  publicShare: string;
  // signed and encrypted gpg armor
  encryptedPrivateShare: string;
  chaincode: string;
};

// NShare with information needed to decrypt and verify a GPG mesasge
export type DecryptableNShare = {
  nShare: EncryptedNShare;
  recipientPrivateArmor: string;
  senderPublicArmor: string;
};

// Final TSS "Keypair"
export type CombinedKey = {
  commonKeychain: string;
  signingMaterial: SigningMaterial;
};

// Private portion of a TSS key, this must be handled like any other private key
export type SigningMaterial = {
  pShare: ECDSA.PShare;
  bitgoNShare: ECDSA.NShare;
  backupNShare?: ECDSA.NShare;
  userNShare?: ECDSA.NShare;
};

export type CreateCombinedKeyParams = {
  keyShare: ECDSA.KeyShare;
  encryptedNShares: DecryptableNShare[];
  commonKeychain: string;
};
