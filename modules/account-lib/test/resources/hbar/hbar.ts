import { KeyPair } from '../../../src/coin/hbar/keyPair';

// ACCOUNT_1 has public and private keys with prefix
export const ACCOUNT_1 = {
  accountId: '0.0.81320',
  prvKeyWithPrefix: '302e020100300506032b65700422042062b0b669de0ab5e91b4328e1431859a5ca47e7426e701019272f5c2d52825b01',
  pubKeyWithPrefix: '302a300506032b65700321005a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf9',
  privateKeyBytes: Uint8Array.from(
    Buffer.from('62b0b669de0ab5e91b4328e1431859a5ca47e7426e701019272f5c2d52825b01', 'hex'),
  ),
  publicKeyBytes: Uint8Array.from(
    Buffer.from('5a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf9', 'hex'),
  ),
};

export const OPERATOR = {
  accountId: '0.0.75861',
  publicKey: '302a300506032b6570032100d32b7b1eb103c10a6c8f6ec575b8002816e9725d95485b3d5509aa8c89b4528b',
  privateKey: '302e020100300506032b65700422042088b5af9484cef4b0aab6e0ba1002313fdfdfacfdf23d6d0957dc5f2c24fc3b81',
};

// ACCOUNT_2 has public and private keys without prefix
export const ACCOUNT_2 = {
  accountId: '0.0.75861',
  privateKey: '5bb72603f237c0993f7973d37fdade32c71aa94aee686aa79d260acba1882d9a',
  publicKey: '592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f8831261',
};

// ACCOUNT_3 has public and private keys without prefix
export const ACCOUNT_3 = {
  accountId: '0.0.78963',
  privateKey: '310a775bcc36016275d64cb8e4508e19437708852e42a3948a641b664be800a9',
  publicKey: 'fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e91',
};

export const ed25519PrivKeyPrefix = '302e020100300506032b657004220420';

export const ed25519PubKeyPrefix = '302a300506032b6570032100';

export const OWNER1 = ACCOUNT_1.pubKeyWithPrefix;

export const OWNER2 = ACCOUNT_2.publicKey;

export const OWNER3 = ACCOUNT_3.publicKey;

export const FEE = '1000000000';

export const VALID_ADDRESS = { address: '10.0.24141' };

export const INVALID_ADDRESS = { address: '1002.4141' };

export const WALLET_INITIALIZATION =
  '229f010a100a080888e1e0f8051000120418d5d00412021804188094ebdc03220208785a7d0a722a700802126c0a2212201c5b8332673e2bdd7d677970e549e05157ea6a94f41a5da5020903c1c391f8ef0a221220265f7cc91c0330ef27a626ff8688da761ab0543d33ba63c8315e2c91b6c595af0a22122003ad12643db2a6ba5cf8a1da14d4bd5ee46625f88886d01cc70d2d9c6ee2266610004a0508d0c8e103';

export const NON_SIGNED_TRANSFER_TRANSACTION =
  '224d0a180a0c089ded8af90510aac5d8b10112080800100018a8fb0412070800100018a912188094ebdc0322020878721e0a1c0a0c0a080800100018a8fb0410130a0c0a080800100018d5d0041014';

export const SIGNED_MAINNET_TRANSFER_TRANSACTION_ID =
  '03ecb93d293fc6f3692efa72b049eb0adeeca1923ef22f5c05b6304964b513d6a2ff94df3d148bc940bff3011acf9565';

export const SIGNED_MAINNET_TRANSFER_TRANSACTION =
  '1acc010a640a201b34d547b392e17da4eae3e0ff9be421a4f143907e44826983b70a927a1357291a407850ab62c0641d9d48c8606beb3766216f4ad3d0a561e0fde899b0dd097d5918297e95501aa0e1e7d04aef150237e2301533c35133d89a4de4a04f87f292c4030a640a20c10789d379cabf39a055a9ce296e724d5abc255c38fd8432d1a583281dbc1e201a409bd5c84200a29001d43111a15f9a3deef878119ba86d969fb92e4810ceccefb9cebd9ef0a6d80c6a09f73edc7c66e1388fb06152b71344d6f669933762fcfc0c22500a180a0c0894cba28306109faab4800112080800100018988e01120608001000180418a5b9072202087872240a220a0f0a080800100018988e0110ffc1d72f0a0f0a080800100018f8cf031080c2d72f';

export const SIGNED_TRANSFER_TRANSACTION =
  '1a660a640a205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf91a406163af39b919ff272be33f6b1deee895bd2f87759c728ab61a1a720bfdc59e7b9d6317d787511446667691f2bec731046b8fb024fd208e3cfab95cb258ffec0c224d0a180a0c089ded8af90510aac5d8b10112080800100018a8fb0412070800100018a912188094ebdc0322020878721e0a1c0a0c0a080800100018a8fb0410130a0c0a080800100018d5d0041014';

export const THREE_TIMES_SIGNED_TRANSACTION =
  '1ab2020a640a205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf91a40b39c87399a9f43523ca5464fe3da4c603c456e9aec9def08bc1c874db19164e81db7911a2da718a53bc8bb71414aecd2f8b69812524874de9e191ff207369a010a640a20592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f88312611a403000eca724dcd881f3487ef0401b71a77a7d02d52b500140b585f8cc54810680f99544c9f9883be1930a1b5245f47cce4dd5c3d765788deee5831ae230874c090a640a20fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e911a40b30cb11259f13e3c433216ed62195f502698d9143fdaed2f027fbc46a0a826e9cd744bb3806acf5abadc4cd31cf5109fe6108aacac4a414c5665991480be8703224c0a180a0c089ded8af90510aac5d8b10112080800100018a8fb041206080010001804188094ebdc0322020878721e0a1c0a0c0a080800100018a8fb0410130a0c0a080800100018d5d0041014';

export const ENCODED_TRANSACTION = 'not defined';

export const errorMessageOddLengthOrNonHexPrivateKey = 'Invalid private key length. Must be a hex and multiple of 2';

export const errorMessageInvalidPrivateKey = 'Invalid private key';

export const errorMessageInvalidPublicKey = 'Invalid public key:';

export const errorMessageMissingPrivateKey = 'Missing private key';

export const errorMessageNotPossibleToDeriveAddress = 'Address derivation is not supported in Hedera';

export const errorMessageFailedToParse = 'Failed to parse correct key';

export const INVALID_KEYPAIR_PRV = new KeyPair({
  prv: '8CAA00AE63638B0542A304823D66D96FF317A576F692663DB2F85E60FAB2590C',
});

export const KEYPAIR_PRV = new KeyPair({
  prv: '302e020100300506032b65700422042062b0b669de0ab5e91b4328e1431859a5ca47e7426e701019272f5c2d52825b01',
});

export const WALLET_TXDATA = Uint8Array.from(
  Buffer.from(
    '22a3010a140a0c0883aa91f9051080feab9b01120418d5d00412021804188094ebdc03220208785a7d0a722a700802126c0a2212205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf90a221220592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f88312610a221220fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e9110004a0508d0c8e103',
    'hex',
  ),
);

export const WALLET_SIGNED_TRANSACTION =
  '1a660a640a205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf91a40ff00c43d4da6d33abf90b2de7d36db8cea62248a6b8ef35be7741c43e762f1208fe5224ac79cd53e59df48913418e976320f789a091cf67a23278a12781b490d22a3010a140a0c0883aa91f9051080feab9b01120418d5d00412021804188094ebdc03220208785a7d0a722a700802126c0a2212205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf90a221220592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f88312610a221220fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e9110004a0508d0c8e103';

export const WALLET_BUILDER_SIGNED_TRANSACTION =
  '1a660a640a20d32b7b1eb103c10a6c8f6ec575b8002816e9725d95485b3d5509aa8c89b4528b1a4067721b81107b0f7f6c94415bbc52591273f4c6f32dd904ec80d64ba956a71313bba6fafa1139fd4f0e05a466758dd228f76681c41007baaf407004749e518e0522ab010a180a0c089ded8af90510aac5d8b10112080800100018d5d0041206080010001804188094ebdc03220208785a7d0a722a700802126c0a2212205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf90a221220592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f88312610a221220fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e9110004a0508d0c8e103';

export const WALLET_BUILDER_SIGNED_TWICE_TRANSACTION =
  '1acc010a640a20d32b7b1eb103c10a6c8f6ec575b8002816e9725d95485b3d5509aa8c89b4528b1a4067721b81107b0f7f6c94415bbc52591273f4c6f32dd904ec80d64ba956a71313bba6fafa1139fd4f0e05a466758dd228f76681c41007baaf407004749e518e050a640a205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf91a400b755558e708dc6119f02da32c647747aa2c7beae4feec0b627f46b2679c525a5ce0646a0b011beb260310e5b7c9890848f1a1d6e3759b116ebd7aca1f0f3c0e22ab010a180a0c089ded8af90510aac5d8b10112080800100018d5d0041206080010001804188094ebdc03220208785a7d0a722a700802126c0a2212205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf90a221220592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f88312610a221220fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e9110004a0508d0c8e103';

export const WALLET_INIT_2_OWNERS =
  '227f0a140a0c089ded8af90510aac5d8b101120418d5d00412021804188094ebdc03220208785a590a4e2a4c080212480a2212205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf90a221220592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f883126110004a0508d0c8e103';

export const SIGNED_TOKEN_TRANSFER_TRANSACTION =
  '1a660a640a205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf91a40bfab36732c2efdd7ef04bbd554ce8fb82f08b871545e992d2f014c19f2b0c5d3c0d15b93c520906e1a959e7818135b252e3f9582103c27c31dc10bbb281ca60622580a180a0c089ded8af90510aac5d8b10112080800100018a8fb0412070800100018a912188094ebdc0322020878722912270a090800100018d3fa8a01120c0a080800100018a8fb041013120c0a080800100018d5d0041014';
export const NON_SIGNED_TOKEN_TRANSFER_TRANSACTION =
  '22580a180a0c089ded8af90510aac5d8b10112080800100018a8fb0412070800100018a912188094ebdc0322020878722912270a090800100018d3fa8a01120c0a080800100018a8fb041013120c0a080800100018d5d0041014';

export const THREE_TIMES_SIGNED_TOKEN_TRANSACTION =
  '1ab2020a640a205a9111b5e6881ff20b9243a42ac1a9a67fa16cd4f01e58bab30c1fe611ea8cf91a404902d04342738ccd23191f17c33a965c0ba43548feefb123f544f66049ad11e61123ef0499d29feef62669b3556cb398286c00322012193e439185235970770a0a640a20592a4fbb7263c59d450e651df96620dc9208ee7c7d9d6f2fdcb91c53f88312611a40fcace05677bb9c53d7b664e35de9f6e2642543c7f29699c3f99de678e6317d945f656b5f7f84b14daf716ded18c97eaf4a51e08151d6b0cca2aab326708b2b0f0a640a20fa344793601cef71348f994f30a168c2dd55f357426a180a5a724d7e03585e911a4006e57dad8a7fcd57cc76c96d506a5ebcc58a64bdeb5e08093d3d236980fafcb523e19d27ebf610367e08bdfe4e5cebc3e2c2cb8dee5c799661c3dd91dd1b780f22570a180a0c089ded8af90510aac5d8b10112080800100018a8fb041206080010001804188094ebdc0322020878722912270a090800100018d3fa8a01120c0a080800100018a8fb041013120c0a080800100018d5d0041014';
