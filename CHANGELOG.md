# Changelog

## Next version

### Changes

* **networks**: change the default gas adjustment parameter to `1.5` instead of `1.2` ([#153](https://github.com/archway-network/archway-cli/pull/153))
* **build**: updated the CosmWasm Optimizer image to `0.12.11` ([#155](https://github.com/archway-network/archway-cli/pull/155))
* **build**: enable rust backtrace in optimizer ([#156](https://github.com/archway-network/archway-cli/pull/156))
* **archwayd**: use the `archwaynetwork/archwayd:v0.2.0` tag by default ([#159](https://github.com/archway-network/archway-cli/pull/159))
* **archwayd**: connect the container to the host network to allow interaction with a node running on the host machine ([#159](https://github.com/archway-network/archway-cli/pull/159))

### Bug Fixes

* **build**: fixed error when the CosmWasm Optimizer image didn't exist in the local environment ([#155](https://github.com/archway-network/archway-cli/pull/155))
* **build**: fixed error when a build container is already running in the background ([#157](https://github.com/archway-network/archway-cli/pull/157))
* **store**: fixed error when validating the stored wasm file on-chain ([#158](https://github.com/archway-network/archway-cli/pull/158))

### Breaking Changes

* **networks**: removed `torii` from the networks list ([#153](https://github.com/archway-network/archway-cli/pull/153))

## [1.3.0](https://github.com/archway-network/archway-cli/compare/1.2.3...1.3.0) (2023-01-20)

### Features

* **archwayd:** use the minimum gas fee in all transactions ([#120](https://github.com/archway-network/archway-cli/pull/120))
* **archwayd:** set metadata using the new rewards module ([#121](https://github.com/archway-network/archway-cli/pull/121))
* **history:** list deployments for current chain ([#126](https://github.com/archway-network/archway-cli/pull/126))
* **cargo:** parse metadata for workspaces ([#127](https://github.com/archway-network/archway-cli/pull/127))
* **build:** use the rust-optimizer Docker image instead of wasm-opt ([#128](https://github.com/archway-network/archway-cli/pull/128))
* **config:** initialize config files in existing projects ([#131](https://github.com/archway-network/archway-cli/pull/131))
* **network:** enable local network [726c452](https://github.com/archway-network/archway-cli/commit/726c45272d126ddd355c242aefa209346d3b539d)
* **config:** store project name in deployment history ([#137](https://github.com/archway-network/archway-cli/pull/137))

### Bug Fixes

* **cargo:** check current path to fetch metadata ([#124](https://github.com/archway-network/archway-cli/pull/124))
* **cli:** fail fast when transactions do not succeed ([#122](https://github.com/archway-network/archway-cli/pull/122))
* **metadata:** typo in --rewards-address flag ([#123](https://github.com/archway-network/archway-cli/pull/123))

### Security Fixes

* **deps**: bump json5 from 2.2.1 to 2.2.3 ([#133](https://github.com/archway-network/archway-cli/pull/133))

### Breaking Changes

* **cli**: deprecate support for nodejs 14 ([#130](https://github.com/archway-network/archway-cli/pull/130))
* **cli**: deprecate the `run` command ([#125](https://github.com/archway-network/archway-cli/pull/125))
* **cli**: deprecate the `test` command ([#132](https://github.com/archway-network/archway-cli/pull/132))
* **cli:** renamed the `configure` command to `config` ([#131](https://github.com/archway-network/archway-cli/pull/131))
* **build:**: Docker is now a hard requirement ([#128](https://github.com/archway-network/archway-cli/pull/128))