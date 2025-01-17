import EDDSAMethods, { EDDSAMethodTypes } from './eddsa';
import ECDSAMethods, { ECDSAMethodTypes } from './ecdsa';

export { EDDSAMethods, EDDSAMethodTypes, ECDSAMethods, ECDSAMethodTypes };
export { ShareKeyPosition } from './types';

// exporting this types for backward compatibility.
export {
  createCombinedKey,
  createUserSignShare,
  createUserToBitGoGShare,
  offerUserToBitgoRShare,
  getBitgoToUserRShare,
  sendUserToBitgoGShare,
  getTxRequest,
  sendSignatureShare,
  encryptYShare,
  EncryptedYShare,
  DecryptableYShare,
  CombinedKey,
  SigningMaterial,
} from './eddsa';
