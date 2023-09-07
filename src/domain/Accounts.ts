import { Coin, StargateClient } from '@cosmjs/stargate';
import { HdPath } from '@cosmjs/crypto';

import { NotFoundError } from '@/exceptions';
import { FileKeystore, KeystoreBackend, OsKeystore, TestKeystore } from '@/domain';
import { GLOBAL_CONFIG_PATH } from './Config';
import { assertIsValidAddress, bold, yellow } from '@/utils';

import {
  Account,
  AccountBalancesJSON,
  AccountBase,
  AccountType,
  AccountWithSigner,
  AccountsParams,
  KeystoreBackendType,
  PublicKey,
} from '@/types';
import { Prompts } from '@/services';

export const SECRET_SERVICE_NAME = 'io.archway.cli';
export const KEY_FILES_PATH = `${GLOBAL_CONFIG_PATH}/keys`;
export const ENTRY_TAG_SEPARATOR = '<-_>';
export const ENTRY_SUFFIX = 'account';
export const TEST_ENTRY_SUFFIX = 'test';
export const DEFAULT_ADDRESS_BECH_32_PREFIX = 'archway';

/**
 * Accounts manager
 */
export class Accounts {
  private _keystore: KeystoreBackend;

  /**
   * @param keystore - Keystore backend that will keep the account's data
   */
  constructor(keystore: KeystoreBackend) {
    this._keystore = keystore;
  }

  get keystore(): KeystoreBackend {
    return this._keystore;
  }

  /**
   * Loads all the available keys
   *
   * @param customKeysPath - Optional - Additional path to check for key files
   * @returns Promise containing an instance of {@link Accounts}
   */
  static async init(type: KeystoreBackendType, params?: AccountsParams): Promise<Accounts> {
    let keystore: KeystoreBackend;
    switch (type) {
      case KeystoreBackendType.os:
        keystore = new OsKeystore(params?.serviceName || SECRET_SERVICE_NAME);
        break;
      case KeystoreBackendType.file:
        keystore = new FileKeystore(params?.filesPath || KEY_FILES_PATH);
        break;
      case KeystoreBackendType.test:
        keystore = new TestKeystore(params?.filesPath || KEY_FILES_PATH);
        break;
    }

    return new Accounts(keystore);
  }

  /**
   * Get a formatted version of the public key
   *
   * @param publicKey - Instance of {@link PublicKey} to be printed
   * @returns Pretty formatted string
   */
  static prettyPrintPublicKey(publicKey: PublicKey): string {
    return `${bold('Public Key')}\n  ${bold('Type:')} ${publicKey['@type']}\n  ${bold('Key:')} ${publicKey.key}`;
  }

  /**
   * Get a formatted version of the name and address
   *
   * @param publicKey - Instance of {@link AccountBase} to be printed
   * @returns Pretty formatted string
   */
  static prettyPrintNameAndAddress(account: AccountBase): string {
    return `${bold('Name:')} ${account.name}\n${bold('Address:')} ${account.address}${
      account.type === AccountType.LEDGER ? `\n${yellow('Ledger account')}` : ''
    }`;
  }

  /**
   * Create a new account in the keyring
   *
   * @param name - Account name
   * @param type - {@link AccountType} value
   * @param mnemonicOrPrivateKey - Optional - Existing mnemonic or private key to use for the new account
   * @param hdPath - Optional - HD path of the account
   * @returns Promise containing an instance of {@link Account}
   */
  async new(name: string, type: AccountType, mnemonicOrPrivateKey?: string, hdPath?: HdPath): Promise<Account> {
    return this._keystore.add(name, type, mnemonicOrPrivateKey, hdPath);
  }

  /**
   * Get a single account by name or address, without mnemonic, throws error if not found
   *
   * @param nameOrAddress - Account name or account address to search by
   * @returns Promise containing an instance of {@link Account}
   */
  async get(nameOrAddress: string): Promise<Account> {
    const account = await this.keystore.get(nameOrAddress);

    if (!account) throw new NotFoundError('Account', nameOrAddress);

    return account;
  }

  /**
   * Get a single account by name or address with its signer, if not provided will ask for it on a prompt.
   * Throws error if the account is not found
   *
   * @param nameOrAddress - Optional - Account name or account address to search by
   * @param prefix - Optional - Bech 32 prefix for the address, defaults to 'archway'
   * @param defaultAccount - Optional - Default account name or account address
   * @returns Promise containing an instance of {@link AccountWithSigner}
   */
  async getWithSigner(nameOrAddress?: string, defaultAccount?: string, prefix = DEFAULT_ADDRESS_BECH_32_PREFIX): Promise<AccountWithSigner> {
    let searchAccount = nameOrAddress || defaultAccount;

    if (!searchAccount) searchAccount = await Prompts.fromAccount();

    const account = await this.keystore.getWithSigner(searchAccount, prefix);

    if (!account) throw new NotFoundError('Account', nameOrAddress);

    return account;
  }

  /**
   * Get a list of the accounts in the keystore
   * @returns Promise containing an array with all the accounts in the keystore
   */
  async list(): Promise<Account[]> {
    return this.keystore.list();
  }

  /**
   * Get a list of the accounts in the keystore, only by name and address
   * @returns Promise containing an array with all the accounts in the keystore
   */
  async listNameAndAddress(): Promise<AccountBase[]> {
    return this.keystore.listNameAndAddress();
  }

  /**
   * Remove an account by name or address
   *
   * @param nameOrAddress - Account name or account address to remove by
   * @returns Empty promise
   */
  async remove(nameOrAddress: string): Promise<void> {
    return this.keystore.remove(nameOrAddress);
  }

  /**
   * Query the balance of an account
   *
   * @param client - Stargate client to use when querying
   * @param nameOrAddress - Account name or account address to search by
   * @returns Promise containing the balances result
   */
  async queryBalance(client: StargateClient, nameOrAddress: string): Promise<AccountBalancesJSON> {
    const accountInfo = await this.keystore.assertAccountExists(nameOrAddress);

    const balances = await client.getAllBalances(accountInfo.address);

    return {
      account: {
        name: accountInfo.name,
        address: accountInfo.address,
        balances: balances as Coin[],
      },
    };
  }

  /**
   * Create an instance of {@link AccountBase} from an address, getting the name if found in keyring
   *
   * @param address - Account address to search by
   * @param prefix - Optional - Bech 32 prefix for the address, defaults to 'archway'
   * @returns Promise containing an instance of {@link AccountBase}
   */
  async accountBaseFromAddress(address: string, prefix = DEFAULT_ADDRESS_BECH_32_PREFIX): Promise<AccountBase> {
    const found = await this.keystore.findNameAndAddressInList(address);

    if (!found) assertIsValidAddress(address, prefix);

    return {
      name: found?.name || '',
      address: found?.address || address,
      type: found?.type || AccountType.LOCAL,
    };
  }
}
