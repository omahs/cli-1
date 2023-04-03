import { Flags } from '@oclif/core';
import { BaseCommand } from '../../lib/base';
import { DeploymentAction } from '../../types/Deployment';
import { AllDeployments } from '../../domain/AllDeployments';

export default class ConfigDeployments extends BaseCommand<typeof ConfigDeployments> {
  static summary = 'Lists deployments for the currently selected network or others, depending on the criteria';
  static flags = {
    chain: Flags.string(),
    action: Flags.string({ options: Object.values(DeploymentAction) }),
    contract: Flags.string({ aliases: ['c'] }),
  };

  public async run(): Promise<void> {
    const deployments = await AllDeployments.open();

    this.log(JSON.stringify(deployments.data))
  }
}