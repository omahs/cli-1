/* eslint-disable camelcase */
import { UploadResult } from '@cosmjs/cosmwasm-stargate';

export const dummyStoreTransaction: UploadResult = {
  originalSize: 126_797,
  originalChecksum: '7994a044ed70c1fad224af08e910dc893643ee6f5069e0eb124bdd4f92759dca',
  compressedSize: 47_022,
  compressedChecksum: '6beb49c19c9c5d35aef4e8c4995acf436ff495295e73a64793ab872c0835d888',
  codeId: 975,
  logs: [
    {
      msg_index: 0,
      log: '',
      events: [
        {
          type: 'message',
          attributes: [
            {
              key: 'action',
              value: '/cosmwasm.wasm.v1.MsgStoreCode',
            },
            {
              key: 'module',
              value: 'wasm',
            },
            {
              key: 'sender',
              value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
            },
          ],
        },
        {
          type: 'store_code',
          attributes: [
            {
              key: 'code_checksum',
              value: '7994a044ed70c1fad224af08e910dc893643ee6f5069e0eb124bdd4f92759dca',
            },
            {
              key: 'code_id',
              value: '975',
            },
          ],
        },
      ],
    },
  ],
  height: 2_189_275,
  transactionHash: 'E2D591CADF02BF7318E1D4D5009F6D67E2E148216CE6AFCE79BB5395A16B2696',
  events: [
    {
      type: 'message',
      attributes: [
        {
          key: 'action',
          value: '/cosmwasm.wasm.v1.MsgStoreCode',
        },
        {
          key: 'module',
          value: 'wasm',
        },
        {
          key: 'sender',
          value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
        },
      ],
    },
    {
      type: 'store_code',
      attributes: [
        {
          key: 'code_checksum',
          value: '7994a044ed70c1fad224af08e910dc893643ee6f5069e0eb124bdd4f92759dca',
        },
        {
          key: 'code_id',
          value: '975',
        },
      ],
    },
  ],
  gasWanted: 1_199_279,
  gasUsed: 935_691,
};

export const dummyInstantiateTransaction = {
  contractAddress: 'archway1l3n05jjyrku0my3ahyg66q95jvstpjnn2xfkyw9xemz5zvl5rssqmnlr0q',
  logs: [
    {
      msg_index: 0,
      log: '',
      events: [
        {
          type: 'instantiate',
          attributes: [
            {
              key: '_contract_address',
              value: 'archway1l3n05jjyrku0my3ahyg66q95jvstpjnn2xfkyw9xemz5zvl5rssqmnlr0q',
            },
            {
              key: 'code_id',
              value: '100',
            },
          ],
        },
        {
          type: 'message',
          attributes: [
            {
              key: 'action',
              value: '/cosmwasm.wasm.v1.MsgInstantiateContract',
            },
            {
              key: 'module',
              value: 'wasm',
            },
            {
              key: 'sender',
              value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
            },
          ],
        },
        {
          type: 'wasm',
          attributes: [
            {
              key: '_contract_address',
              value: 'archway1l3n05jjyrku0my3ahyg66q95jvstpjnn2xfkyw9xemz5zvl5rssqmnlr0q',
            },
            {
              key: 'method',
              value: 'instantiate',
            },
            {
              key: 'owner',
              value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
            },
          ],
        },
      ],
    },
  ],
  height: 271_471,
  transactionHash: '49183004474DF2ED15B92663F5FDB0766C9C0608E0EA0944F2B1166F0BC59DA5',
  events: [
    {
      type: 'coin_spent',
      attributes: [
        {
          key: 'spender',
          value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
        },
        {
          key: 'amount',
          value: '197258400000000000aconst',
        },
      ],
    },
    {
      type: 'coin_received',
      attributes: [
        {
          key: 'receiver',
          value: 'archway17xpfvakm2amg962yls6f84z3kell8c5l9jlyp2',
        },
        {
          key: 'amount',
          value: '197258400000000000aconst',
        },
      ],
    },
    {
      type: 'transfer',
      attributes: [
        {
          key: 'recipient',
          value: 'archway17xpfvakm2amg962yls6f84z3kell8c5l9jlyp2',
        },
        {
          key: 'sender',
          value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
        },
        {
          key: 'amount',
          value: '197258400000000000aconst',
        },
      ],
    },
    {
      type: 'message',
      attributes: [
        {
          key: 'sender',
          value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
        },
      ],
    },
    {
      type: 'tx',
      attributes: [
        {
          key: 'fee',
          value: '197258400000000000aconst',
        },
      ],
    },
    {
      type: 'tx',
      attributes: [
        {
          key: 'acc_seq',
          value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv/7',
        },
      ],
    },
    {
      type: 'tx',
      attributes: [
        {
          key: 'signature',
          value: 'LLQ9K/x3jq3l+KoKluwaFYFj0p+dAb8M5nH3KAJSHC48Z7/BzFKNgTD6D8RHtbS7iZ1l6yCl9+nev2KlscUHRA==',
        },
      ],
    },
    {
      type: 'message',
      attributes: [
        {
          key: 'action',
          value: '/cosmwasm.wasm.v1.MsgInstantiateContract',
        },
      ],
    },
    {
      type: 'message',
      attributes: [
        {
          key: 'module',
          value: 'wasm',
        },
        {
          key: 'sender',
          value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
        },
      ],
    },
    {
      type: 'instantiate',
      attributes: [
        {
          key: '_contract_address',
          value: 'archway1l3n05jjyrku0my3ahyg66q95jvstpjnn2xfkyw9xemz5zvl5rssqmnlr0q',
        },
        {
          key: 'code_id',
          value: '100',
        },
      ],
    },
    {
      type: 'wasm',
      attributes: [
        {
          key: '_contract_address',
          value: 'archway1l3n05jjyrku0my3ahyg66q95jvstpjnn2xfkyw9xemz5zvl5rssqmnlr0q',
        },
        {
          key: 'method',
          value: 'instantiate',
        },
        {
          key: 'owner',
          value: 'archway1w8uad5ddvadfv3vdjrt3d8f3famnrg4msd43zv',
        },
      ],
    },
  ],
  gasWanted: 219_176,
  gasUsed: 184_007,
};
