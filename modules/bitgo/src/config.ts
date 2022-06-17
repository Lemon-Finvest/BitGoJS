import * as _ from 'lodash';
import { OfcTokenConfig } from './v2/coins/ofcToken';
import { Erc20TokenConfig } from './v2/coins/erc20Token';
import { StellarTokenConfig } from './v2/coins/stellarToken';
import { CeloTokenConfig } from './v2/coins/celoToken';
import { EosTokenConfig } from './v2/coins/eosToken';
import { AlgoTokenConfig, formattedAlgoTokens } from '@bitgo/sdk-coin-algo';
import { AvaxcTokenConfig } from './v2/coins/avaxcToken';
import {
  coins,
  Erc20Coin,
  StellarCoin,
  OfcCoin,
  CeloCoin,
  CoinKind,
  NetworkType,
  EosCoin,
  Networks,
  AvaxERC20Token,
} from '@bitgo/statics';
import { EnvironmentName, Environments, KrsProvider } from '@bitgo/sdk-core';
import BigNumber from 'bignumber.js';

export interface Tokens {
  bitcoin: {
    eth: {
      tokens: Erc20TokenConfig[];
    };
    xlm: {
      tokens: StellarTokenConfig[];
    };
    algo: {
      tokens: AlgoTokenConfig[];
    };
    ofc: {
      tokens: OfcTokenConfig[];
    };
    celo: {
      tokens: CeloTokenConfig[];
    };
    eos: {
      tokens: EosTokenConfig[];
    };
    avaxc: {
      tokens: AvaxcTokenConfig[];
    };
  };
  testnet: {
    eth: {
      tokens: Erc20TokenConfig[];
    };
    xlm: {
      tokens: StellarTokenConfig[];
    };
    algo: {
      tokens: AlgoTokenConfig[];
    };
    ofc: {
      tokens: OfcTokenConfig[];
    };
    celo: {
      tokens: CeloTokenConfig[];
    };
    eos: {
      tokens: EosTokenConfig[];
    };
    avaxc: {
      tokens: AvaxcTokenConfig[];
    };
  };
}

// Get the list of ERC-20 tokens from statics and format it properly
const formattedErc20Tokens = coins.reduce((acc: Erc20TokenConfig[], coin) => {
  if (coin instanceof Erc20Coin) {
    let baseCoin: string;
    switch (coin.network) {
      case Networks.main.ethereum:
        baseCoin = 'eth';
        break;
      case Networks.test.kovan:
        baseCoin = 'teth';
        break;
      case Networks.test.goerli:
        baseCoin = 'gteth';
        break;
      default:
        throw new Error(`Erc20 token ${coin.name} has an unsupported network`);
    }

    acc.push({
      type: coin.name,
      coin: baseCoin,
      network: coin.network.type === NetworkType.MAINNET ? 'Mainnet' : 'Testnet',
      name: coin.fullName,
      tokenContractAddress: coin.contractAddress.toString().toLowerCase(),
      decimalPlaces: coin.decimalPlaces,
    });
  }
  return acc;
}, []);

export const ethGasConfigs = {
  minimumGasPrice: 1000000000, // minimum gas price a user can provide (1 Gwei)
  defaultGasPrice: 20000000000, // default gas price if estimation fails (20 Gwei)
  maximumGasPrice: 2500000000000, // minimum gas price a user can provide (2500 Gwei)
  defaultGasLimit: 500000, // Default gas limit we set for contract send
  defaultGasLimitTokenSend: 1000000, // Default gas limit we set for token send
  minimumGasLimit: 30000,    // minimum gas limit a user can set for a send
  maximumGasLimit: 20000000, // Customers cannot set gas limits beyond this amount
};

export const NearGasConfigs = {
  transfer_cost: {
    send_sir: new BigNumber(115123062500),
    send_not_sir: new BigNumber(115123062500),
    execution: new BigNumber(115123062500),
  },
  action_receipt_creation_config: {
    send_sir: new BigNumber(108059500000),
    send_not_sir: new BigNumber(108059500000),
    execution: new BigNumber(108059500000),
  },
};
// Get the list of Stellar tokens from statics and format it properly
const formattedStellarTokens = coins.reduce((acc: StellarTokenConfig[], coin) => {
  if (coin instanceof StellarCoin) {
    acc.push({
      type: coin.name,
      coin: coin.network.type === NetworkType.MAINNET ? 'xlm' : 'txlm',
      network: coin.network.type === NetworkType.MAINNET ? 'Mainnet' : 'Testnet',
      name: coin.fullName,
      decimalPlaces: coin.decimalPlaces,
    });
  }
  return acc;
}, []);

// Get the list of OFC tokens from statics and format it properly
const formattedOfcCoins = coins.reduce((acc: OfcTokenConfig[], coin) => {
  if (coin instanceof OfcCoin) {
    acc.push({
      type: coin.name,
      coin: 'ofc',
      backingCoin: coin.asset,
      name: coin.fullName,
      decimalPlaces: coin.decimalPlaces,
      isFiat: coin.kind === CoinKind.FIAT,
    });
  }
  return acc;
}, []);

const formattedCeloTokens = coins.reduce((acc: CeloTokenConfig[], coin) => {
  if (coin instanceof CeloCoin) {
    acc.push({
      type: coin.name,
      coin: coin.network.type === NetworkType.MAINNET ? 'celo' : 'tcelo',
      network: coin.network.type === NetworkType.MAINNET ? 'Mainnet' : 'Testnet',
      name: coin.fullName,
      tokenContractAddress: coin.contractAddress.toString().toLowerCase(),
      decimalPlaces: coin.decimalPlaces,
    });
  }
  return acc;
}, []);

const formattedEosTokens = coins.reduce((acc: EosTokenConfig[], coin) => {
  if (coin instanceof EosCoin) {
    acc.push({
      type: coin.name,
      coin: coin.network.type === NetworkType.MAINNET ? 'eos' : 'teos',
      network: coin.network.type === NetworkType.MAINNET ? 'Mainnet' : 'Testnet',
      name: coin.fullName,
      tokenContractAddress: coin.contractName.toString().toLowerCase(),
      decimalPlaces: coin.decimalPlaces,
    });
  }
  return acc;
}, []);

const formattedAvaxCTokens = coins.reduce((acc: AvaxcTokenConfig[], coin) => {
  if (coin instanceof AvaxERC20Token) {
    acc.push({
      type: coin.name,
      coin: coin.network.type === NetworkType.MAINNET ? 'avaxc' : 'tavaxc',
      network: coin.network.type === NetworkType.MAINNET ? 'Mainnet' : 'Testnet',
      name: coin.fullName,
      tokenContractAddress: coin.contractAddress.toString().toLowerCase(),
      decimalPlaces: coin.decimalPlaces,
    });
  }
  return acc;
}, []);

export const tokens: Tokens = {
  // network name for production environments
  bitcoin: {
    eth: {
      tokens: formattedErc20Tokens.filter(token => token.network === 'Mainnet'),
    },
    xlm: {
      tokens: formattedStellarTokens.filter(token => token.network === 'Mainnet'),
    },
    algo: {
      tokens: formattedAlgoTokens.filter(token => token.network === 'Mainnet'),
    },
    ofc: {
      tokens: formattedOfcCoins.filter(token => coins.get(token.type).network.type === NetworkType.MAINNET),
    },
    celo: {
      tokens: formattedCeloTokens.filter(token => token.network === 'Mainnet'),
    },
    eos: {
      tokens: formattedEosTokens.filter(token => token.network === 'Mainnet'),
    },
    avaxc: {
      tokens: formattedAvaxCTokens.filter(token => token.network === 'Mainnet'),
    },
  },
  // network name for test environments
  testnet: {
    eth: {
      tokens: formattedErc20Tokens.filter(token => token.network === 'Testnet'),
    },
    xlm: {
      tokens: formattedStellarTokens.filter(token => token.network === 'Testnet'),
    },
    algo: {
      tokens: formattedAlgoTokens.filter(token => token.network === 'Testnet'),
    },
    ofc: {
      tokens: formattedOfcCoins.filter(token => coins.get(token.type).network.type === NetworkType.TESTNET),
    },
    celo: {
      tokens: formattedCeloTokens.filter(token => token.network === 'Testnet'),
    },
    eos: {
      tokens: formattedEosTokens.filter(token => token.network === 'Testnet'),
    },
    avaxc: {
      tokens: formattedAvaxCTokens.filter(token => token.network === 'Testnet'),
    },
  },
};

/**
 * Verify mainnet or testnet tokens
 * @param tokens
 */
const verifyTokens = function (tokens) {
  const verifiedTokens = {};
  _.forEach(tokens, function (token) {
    if (verifiedTokens[token.type]) {
      throw new Error('token : ' + token.type + ' duplicated.');
    }
    verifiedTokens[token.type] = true;

    if (token.tokenContractAddress && token.tokenContractAddress !== _.toLower(token.tokenContractAddress)) {
      throw new Error('token contract: ' + token.type + ' is not all lower case: ' + token.tokenContractAddress);
    }
  });
  return verifiedTokens;
};

const mainnetErc20Tokens = verifyTokens(tokens.bitcoin.eth.tokens);
const mainnetStellarTokens = verifyTokens(tokens.bitcoin.xlm.tokens);
export const mainnetTokens = _.assign({}, mainnetErc20Tokens, mainnetStellarTokens);

const testnetErc20Tokens = verifyTokens(tokens.testnet.eth.tokens);
const testnetStellarTokens = verifyTokens(tokens.testnet.xlm.tokens);
export const testnetTokens = _.assign({}, testnetErc20Tokens, testnetStellarTokens);


export const defaults = {
  maxFee: 0.1e8,
  maxFeeRate: 1000000,
  minFeeRate: 5000,
  fallbackFeeRate: 50000,
  minOutputSize: 2730,
  minInstantFeeRate: 10000,
  bitgoEthAddress: '0x0f47ea803926926f299b7f1afc8460888d850f47',
};

// TODO: once server starts returning eth address keychains, remove bitgoEthAddress
/**
 * Get the default (hardcoded) constants for a particular network.
 *
 * Note that this may not be the complete set of constants, and additional constants may get fetched
 * from BitGo during the lifespan of a BitGo object.
 * @param env
 */
export const defaultConstants = (env: EnvironmentName) => {
  if (Environments[env] === undefined) {
    throw Error(`invalid environment ${env}`);
  }

  const network = Environments[env].network;
  return _.merge({}, defaults, tokens[network]);
};

export type Config = {
  krsProviders: Record<string, KrsProvider>
}
