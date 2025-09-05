import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import { Contract } from "ethers";

/**
 * Deploys the GaslessPollContract
 *
 * @param hre HardhatRuntimeEnvironment object.
 */
const deployGaslessPollContract: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  await deploy("GaslessPollContract", {
    from: deployer,
    // Contract constructor arguments (owner address)
    args: [deployer],
    log: true,
    // autoMine: can be passed to the deploy function to make the deployment process faster on local networks by
    // automatically mining the contract deployment transaction. There is no effect on live networks.
    autoMine: true,
  });

  // Get the deployed contract to interact with it after deploying.
  const gaslessPollContract = await hre.ethers.getContract<Contract>("GaslessPollContract", deployer);
  console.log("👋 GaslessPollContract deployed to:", await gaslessPollContract.getAddress());
  console.log("📊 Initial poll count:", await gaslessPollContract.pollCount());

  // Get batch settings
  const [minBatch, maxBatch] = await gaslessPollContract.getBatchSettings();
  console.log(`⚙️  Batch settings - Min: ${minBatch}, Max: ${maxBatch}`);
};

export default deployGaslessPollContract;

// Tags are useful if you have multiple deploy files and only want to run one of them.
// e.g. yarn deploy --tags GaslessPollContract
deployGaslessPollContract.tags = ["GaslessPollContract"];
