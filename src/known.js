// Well-known contracts. A label lowers no risk by itself; it only tells the user who they are trusting.
export const KNOWN = {
  '0x000000000022d473030f116ddee9f6b43ac78ba3': 'Uniswap Permit2',
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc': 'OpenSea Seaport 1.5',
  '0x0000000000000068f116a894984e2db1123eb395': 'OpenSea Seaport 1.6',
  '0x1e0049783f008a0085193e00003d00cd54003c71': 'OpenSea Conduit',
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': 'Uniswap Universal Router',
  '0x66a9893cc07d91d95644aedd05d03f95e1dba8af': 'Uniswap Universal Router v4',
  '0x10ed43c718714eb63d5aa57b78b54704e256024e': 'PancakeSwap v2 Router',
  '0x13f4ea83d0bd40e75c8222255bc855a974568dd4': 'PancakeSwap Smart Router',
  '0x1111111254eeb25477b68fb85ed929f73a960582': '1inch Router v5',
  '0x111111125421ca6dc452d289314280a0f8842a65': '1inch Router v6',
  '0xdef1c0ded9bec7f1a1670819833240f027b25eff': '0x Exchange Proxy',
  '0x00000000000001ad428e4906ae43d8f9852d0dd6': 'Blur Marketplace',
};

export const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';

export const SELECTORS = {
  '0x095ea7b3': { name: 'approve', args: ['address', 'uint256'], names: ['spender', 'amount'] },
  '0xa22cb465': { name: 'setApprovalForAll', args: ['address', 'bool'], names: ['operator', 'approved'] },
  '0x39509351': { name: 'increaseAllowance', args: ['address', 'uint256'], names: ['spender', 'added'] },
  '0xa9059cbb': { name: 'transfer', args: ['address', 'uint256'], names: ['to', 'amount'] },
  '0x23b872dd': { name: 'transferFrom', args: ['address', 'address', 'uint256'], names: ['from', 'to', 'amountOrId'] },
  '0x42842e0e': { name: 'safeTransferFrom', args: ['address', 'address', 'uint256'], names: ['from', 'to', 'tokenId'] },
  '0x87517c45': { name: 'Permit2.approve', args: ['address', 'address', 'uint160', 'uint48'], names: ['token', 'spender', 'amount', 'expiration'] },
  '0xd505accf': { name: 'permit', args: ['address', 'address', 'uint256', 'uint256', 'uint8', 'bytes32', 'bytes32'], names: ['owner', 'spender', 'value', 'deadline', 'v', 'r', 's'] },
  '0xf2fde38b': { name: 'transferOwnership', args: ['address'], names: ['newOwner'] },
  '0x1249c58b': { name: 'mint', args: [], names: [] },
  '0xa0712d68': { name: 'mint', args: ['uint256'], names: ['quantity'] },
  '0x3ccfd60b': { name: 'withdraw', args: [], names: [] },
};

export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_UINT160 = (1n << 160n) - 1n;
export const MAX_UINT48 = (1n << 48n) - 1n;
