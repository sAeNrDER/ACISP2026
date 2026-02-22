const { ethers } = require('hardhat');

async function main() {
  const [deployer] = await ethers.getSigners();
  const Authorization = await ethers.getContractFactory('Authorization');
  const authorization = await Authorization.deploy(deployer.address);
  await authorization.waitForDeployment();

  const SpentSet = await ethers.getContractFactory('SpentSet');
  const spentSet = await SpentSet.deploy(await authorization.getAddress());
  await spentSet.waitForDeployment();

  const ParamRegistry = await ethers.getContractFactory('ParamRegistry');
  const registry = await ParamRegistry.deploy('0x' + '11'.repeat(64), 1, 3);
  await registry.waitForDeployment();

  const BiometricWallet = await ethers.getContractFactory('BiometricWallet');
  const wallet = await BiometricWallet.deploy(deployer.address, await spentSet.getAddress());
  await wallet.waitForDeployment();

  await (await authorization.setAuthorized(await wallet.getAddress(), true)).wait();

  console.log({
    authorization: await authorization.getAddress(),
    spentSet: await spentSet.getAddress(),
    registry: await registry.getAddress(),
    wallet: await wallet.getAddress(),
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
