import path from 'node:path';
import fs from 'node:fs/promises';
import toml from 'toml';

import { bold, green, red } from '@/utils/style';
import { Contract } from '@/types/Contract';
import { getWorkspaceRoot } from '@/utils/paths';
import { DEFAULT, REPOSITORIES } from '@/config';
import { ConsoleError } from '@/types/ConsoleError';
import { ErrorCodes } from '@/exceptions/ErrorCodes';
import { Cargo } from './Cargo';
import { readSubDirectories } from '@/utils/filesystem';
import { CargoProjectMetadata } from '@/types/Cargo';

/**
 * Manages the contracts' data in the project
 */
export class Contracts {
  private _data: Contract[];
  private _workspaceRoot: string;
  private _contractsRoot: string;

  /**
   * @param data - Array of {@link Contract}
   * @param workspaceRoot - Absolute path of the project's workspace root
   * @param contractsRoot - Path of the directory where contracts will be found
   */
  constructor(data: Contract[], workspaceRoot: string, contractsRoot: string) {
    this._data = data;
    this._workspaceRoot = workspaceRoot;
    this._contractsRoot = contractsRoot;
  }

  get data(): Contract[] {
    return this._data;
  }

  get workspaceRoot(): string {
    return this._workspaceRoot;
  }

  get contractsRoot(): string {
    return this._contractsRoot;
  }

  /**
   * Open the contract files in the project
   *
   * @param workingDir - Optional - Path of the working directory
   * @param contractsPath - Optional - Path where the contracts are in the project
   * @returns Promise containing an instance of {@link Contracts}
   */
  static async open(workingDir?: string, contractsPath?: string): Promise<Contracts> {
    const workspaceRoot = await getWorkspaceRoot(workingDir);

    const contractsRoot = await this.getContractsRoot(workingDir, contractsPath);

    const contractDirectories = await readSubDirectories(contractsRoot);

    const cargoInstances = contractDirectories.map(item => new Cargo(item));

    const data = await Promise.all(cargoInstances.map(item => item.projectMetadata()));

    return new Contracts(
      data.map(item => this.addDeploymentsData(item)),
      workspaceRoot,
      contractsRoot
    );
  }

  /**
   * Convert {@link CargoProjectMetadata} into a {@link Contract} object
   *
   * @param metadata - Project Metadata to parse
   * @param rootPath - Absolute path where the contract is located
   * @returns An instance of {@link Contract}
   */
  static addDeploymentsData(metadata: CargoProjectMetadata): Contract {
    return {
      ...metadata,
      // TO DO Add deployments to Contract class
      deployments: [],
    };
  }

  /**
   * Get the absolute path of the contracts directory
   *
   * @param workingDir - Optional - Path of the working directory
   * @param contractsPath - Optional - Path of the contracts directory
   * @returns Promise containing the absolute path of the contracts directory
   */
  static async getContractsRoot(workingDir?: string, contractsPath?: string): Promise<string> {
    const workspaceRoot = await getWorkspaceRoot(workingDir);
    const contracts = contractsPath || DEFAULT.ContractsRelativePath;

    return path.isAbsolute(contracts) ? contracts : path.join(workspaceRoot, contracts);
  }

  /**
   * Verifies that a project has a valid workspace
   *
   * @param params - Object of type {@link GenerateParams}
   */
  async assertValidWorkspace(): Promise<void> {
    const relativeContracts = `${path.relative(this._workspaceRoot, this._contractsRoot)}/*`;
    const cargoFilePath = path.join(this._workspaceRoot, './Cargo.toml');

    const fileContent = await fs.readFile(cargoFilePath);
    const data = toml.parse(fileContent.toString());

    if (!data?.workspace?.members?.some((item: string) => item === relativeContracts))
      throw new InvalidWorkspaceError(cargoFilePath, relativeContracts);
  }

  /**
   * Create a new contract from one of the archway templates
   *
   * @param name - Contract name
   * @param template - Name of the template to use
   */
  async new(name: string, template: string): Promise<Contract> {
    const cargo = new Cargo();
    await cargo.generate({
      name,
      repository: REPOSITORIES.Templates,
      branch: DEFAULT.TemplateBranch,
      template: template,
      destinationDir: this.contractsRoot,
    });
    const generatedPath = path.join(this.contractsRoot, name);
    const generatedCrate = new Cargo(generatedPath);
    const metadata = await generatedCrate.projectMetadata();
    const result = Contracts.addDeploymentsData(metadata);
    this._data.push(result);

    return result;
  }

  /**
   * Return the list of all contracts
   *
   * @returns Array containing all the contracts
   */
  listContracts(): Contract[] {
    return this._data;
  }

  /**
   * Check if a contract exists by name, if not found throws an error
   *
   * @param contractName - Name of the contract to get
   * @returns void
   */
  assertGetContractByName(contractName: string): void {
    if (!this.getContractByName(contractName)) throw new ContractNameNotFoundError(contractName);
  }

  /**
   * Get a contract by its name
   *
   * @param contractName - Name of the contract to get
   * @returns Instance of {@link Contract} that matches the name, or undefined if not found
   */
  getContractByName(contractName: string): Contract | undefined {
    return this._data.find(item => item.name === contractName);
  }

  /**
   * Get a formatted version of the contracts in the project
   *
   * @returns Promise containing the formatted contracts data
   */
  async prettyPrint(): Promise<string> {
    let contractsList = '';
    for (const item of this._data) {
      contractsList += `\n  ${green(item.name)} (${item.version})`;
    }

    if (!contractsList) contractsList = '(none)';

    return `${bold('Available contracts: ')}${contractsList}`;
  }
}

/**
 * Error when contract name is not found
 */
export class ContractNameNotFoundError extends ConsoleError {
  /**
   * @param contractName - Contract name that triggered the error
   */
  constructor(public contractName: string) {
    super(ErrorCodes.CONTRACT_NAME_NOT_FOUND);
  }

  /**
   * {@inheritDoc ConsoleError.toConsoleString}
   */
  toConsoleString(): string {
    return `${red('Contract with name')} ${bold(this.contractName)} ${red('not found')}`;
  }
}

/**
 * Error when project workspace is invalid
 */
export class InvalidWorkspaceError extends ConsoleError {
  /**
   * @param workspaceRoot - Path of the project's workspace
   * @param requiredWorkspaceMember - Required value in workspace.members array
   */
  constructor(public cargoFilePath: string, public requiredWorkspaceMember: string) {
    super(ErrorCodes.INVALID_WORKSPACE_ERROR);
  }

  /**
   * {@inheritDoc ConsoleError.toConsoleString}
   */
  toConsoleString(): string {
    return `${red('Invalid cargo file')} ${bold(this.cargoFilePath)} ${red(' please make sure it is a workspace and has')} ${bold(
      `"${this.requiredWorkspaceMember}"`
    )} ${red('in the members array')}`;
  }
}
