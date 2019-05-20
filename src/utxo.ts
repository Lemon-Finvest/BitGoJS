import { BaseCoin, CoinFeature, CoinKind, UnderlyingAsset } from './base';
import { UtxoNetwork } from './networks';

export interface UtxoConstructorOptions {
  fullName: string;
  name: string;
  network: UtxoNetwork;
  features: CoinFeature[];
  prefix?: string;
  suffix?: string;
}

export class UtxoCoin extends BaseCoin {
  public static readonly DEFAULT_FEATURES = [
    CoinFeature.UNSPENT_MODEL,
    CoinFeature.CHILD_PAYS_FOR_PARENT,
    CoinFeature.WRAPPED_SEGWIT,
    CoinFeature.NATIVE_SEGWIT,
  ];

  /**
   * Additional fields for utxo coins
   */
  public readonly network: UtxoNetwork;

  constructor(options: UtxoConstructorOptions) {
    super({
      kind: CoinKind.CRYPTO,
      family: options.network.family,
      isToken: false,
      decimalPlaces: 8,
      asset: UnderlyingAsset.SELF,
      prefix: '',
      suffix: options.name,
      ...options,
    });

    this.network = options.network;
  }

  protected disallowedFeatures(): Set<CoinFeature> {
    return new Set([CoinFeature.ACCOUNT_MODEL]);
  }

  protected requiredFeatures(): Set<CoinFeature> {
    return new Set([CoinFeature.UNSPENT_MODEL]);
  }
}

/**
 * Factory function for utxo coin instances.
 *
 * @param name unique identifier of the coin
 * @param fullName Complete human-readable name of the coin
 * @param network Network object for this coin
 * @param prefix? Optional coin prefix. Defaults to empty string
 * @param suffix? Optional coin suffix. Defaults to coin name.
 * @param features? Features of this coin. Defaults to the DEFAULT_FEATURES defined in `UtxoCoin`
 */
export function utxo(
  name: string,
  fullName: string,
  network: UtxoNetwork,
  prefix?: string,
  suffix?: string,
  features: CoinFeature[] = UtxoCoin.DEFAULT_FEATURES
) {
  return Object.freeze(
    new UtxoCoin({
      name,
      fullName,
      network,
      prefix,
      suffix,
      features,
    })
  );
}
