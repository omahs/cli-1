import { getWokspaceRoot } from '../utils/paths';
import path from 'node:path';
import { DefaultChainsRelativePath } from '../config';
import { CosmosChain } from '../types/CosmosSchema';
import fs from 'node:fs/promises';
import { BuiltInChains } from '../services/BuiltInChains';

export class ChainRegistry {
  private _data: CosmosChain[];
  private _path: string;

  constructor(data: CosmosChain[], path: string) {
    this._data = data;
    this._path = path;
  }

  get data(): CosmosChain[] {
    return this._data;
  }

  get path(): string {
    return this._path;
  }

  static async init(chainsDirectory?: string): Promise<ChainRegistry> {
    const directoryPath = chainsDirectory || path.join(await getWokspaceRoot(), DefaultChainsRelativePath);

    let filesList = await fs.readdir(directoryPath);
    filesList = filesList.filter(item => path.extname(item) === '.json');

    const filesRead = await Promise.all<string>(filesList.map(item => fs.readFile(path.join(directoryPath, item), 'utf8')));

    // List of built-in chains that could be added to final result
    const builtInToAdd = { ...BuiltInChains.chainMap };

    // Parse file contents, and check if they override built-in chain info
    const parsedList: CosmosChain[] = [];
    for (const file of filesRead) {
      const parsed: CosmosChain = JSON.parse(file);
      if (BuiltInChains.getChainIds().includes(parsed.chain_id)) {
        delete builtInToAdd[parsed.chain_id];
      }

      parsedList.push(parsed);
    }

    // Create chain registry with the parsed chains and the built-in chains pending to add
    return new ChainRegistry([...parsedList, ...Object.values(builtInToAdd)], directoryPath);
  }

  getChainById(chainId: string): CosmosChain | undefined {
    return this._data.find(item => item.chain_id === chainId);
  }

  async writeChainFile(chain: CosmosChain): Promise<void> {
    const json = JSON.stringify(chain, null, 2);

    fs.writeFile(path.join(this._path, `./${chain.chain_id}.json`), json);
    this._data.push(chain);
  }
}