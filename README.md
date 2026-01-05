# LMGS

This repository implements a group signature scheme using Python and C scripts. The system is composed of multiple scripts that work together for parameter generation, signature creation, and verification.

## Scripts Overview

**1. `GS_merged_params.py`**
- Generates the parameters required for signing and verification in the form of $As = t$.
- Defines matrix and vector dimensions, polynomial ring $\mathcal{R}_q$, and boundary values.
- Each execution produces a `.h` file containing public keys and other parameters.
- **Usage:** Run this script once during the initialization phase. If any parameters are updated, re-run to generate a new `.h` file for the signer and verifier.

**2. `Group_sig_unified.py`**
- Allows vehicles to generate a signature on a message of the form `ts || message` using their assigned secret keys.
- Verifies received signatures using the public keys stored in `GS_merged_params.h`.

**3. `Group_sig_unified1000.py`**
- Performs 1,000 iterations of signature generation to measure average execution time and signature size.

### **System Architecture and Communication Flows**

![Architecture](./images/scheme.jpg)


## Description of the Scheme

The system consists of three main entities:

1. Vehicles
2. Central System (CS), including the Trusted Authority (TA) and Application Servers (AS)
3. Roadside Units (RSU)

### Key Generation and Distribution
- The TA generates public and private keys for both vehicles and RSUs.
- Public parameters are uploaded to RSU and CS, enabling all entities to access them.
- All keys are unique and remain unchanged once generated.

### Vehicle Secret Parameters
- When a vehicle requires its secret parameters, it requests them from the TA.
- The TA provides the tuple $(S_1^{(i)}, S_2^{(i)}, S_3^{(i)}, id_i)$, which are the private group signature keys.
- These keys satisfy the following equation:

$$
[\mathbf{A} \mid \mathbf{B} + id_i \mathbf{G} \mid \mathbf{B}'] 
\begin{bmatrix}
\mathbf{s}_1^{(i)}\\ 
\mathbf{s}_2^{(i)}\\ 
\mathbf{s}_3^{(i)}
\end{bmatrix} = \mathbf{u}.
$$

### Signature Generation and Verification
- Vehicles use their secret parameters to generate anonymous signatures on messages intended for RSUs or other vehicles.
- Signature generation and verification are handled by `Group_sig_unified.py`.
- The RSU or any other entity can verify signatures using the public parameters.
- Signing and verification processes can be executed independently.

## Setup Library

First, you need to set up the **LaZer library**. For installation and instructions, please refer to the official repository: [LaZer on GitHub](https://github.com/lazer-crypto/lazer)
