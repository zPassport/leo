# zPassport (Leo)

Built on zero-knowledge cryptography and the Aleo blockchain, the zPass model enables private identity verification without revealing the underlying data.


zPassport is taking this concept one step further: using official digital passport data as the foundation for issuing zPass credentials. This approach builds directly on the existing infrastructure of trusted government-issued documents, transforming them into verifiable digital credentials. The result is a secure, interoperable bridge between real-world identity and privacy-preserving, verifiable digital identity.

This repository contains the Leo source code for zPassport

<br /> 

## Deployments

| Network | Program Name |
|---|---|
|Testnet| `zpassport_v001.aleo` |
|Mainnet| **TBD** |

## Limitations 
Currently, this version of zPassport faces limitations that prevent its full practical usage.  Aleo doesn't currently support RSA or ECDSA signature verification, so moving the full zPassport minting process on-chain is unfeasible.  This will likely be resolved in the coming weeks/months.  See [here](https://alex-kim.ghost.io/introducing-zpassport/) for more information.
