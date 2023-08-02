/* eslint-disable unicorn/no-static-only-class */
import path from 'node:path';

import { Cargo } from './Cargo';
import { Config } from './Config';
import { DEFAULT, REPOSITORIES } from '@/config';
import { sanitizeDirName } from '@/utils/sanitize';
import { Contracts } from './Contracts';

/**
 * Type of project
 */
export enum ProjectType {
  RUST = 'rust',
}

/**
 * Parameters for a new project
 */
export interface ProjectParams {
  name: string;
  contractTemplate?: string;
  chainId: string;
  contractName: string;
}

/**
 * Allows to create a new project according to parameters
 */
export class NewProject {
  /**
   * Creates a new project
   *
   * @param params - Parameters for new project
   * @param type - Type of project
   */
  static async create(params: ProjectParams, type = ProjectType.RUST): Promise<void> {
    // Sanitize names and build paths
    const workingDir = process.cwd();
    const sanitizedProjectName = sanitizeDirName(params.name);
    const sanitizedContractName = sanitizeDirName(params.contractName);
    const projectDir = path.join(workingDir, sanitizedProjectName);
    const contractsDir = path.join(projectDir, DEFAULT.ContractsRelativePath);

    // Create project depending on type
    switch (type) {
      case ProjectType.RUST:
        await RustProject.create(sanitizedProjectName);
        break;
    }

    // Create config file
    await Config.create(params.chainId, projectDir);

    // Create contract
    if (params.contractTemplate) {
      const contracts = new Contracts([], contractsDir);
      await contracts.new(sanitizedContractName, params.contractTemplate);
    }
  }
}

/**
 * Rust Project class
 */
export class RustProject {
  /**
   * Creates a new rust project with a workspace for multiple contracts
   *
   * @param name - Name of the project
   */
  static async create(name: string): Promise<void> {
    const cargo = new Cargo();
    await cargo.generate({
      name,
      repository: REPOSITORIES.Templates,
      branch: DEFAULT.TemplateBranch,
      template: DEFAULT.WorkspaceTemplate,
    });
  }
}
