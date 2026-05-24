# DID Proxy for AUSF# DID Proxy for AUSF



This is a DID (Decentralized Identifier) generation proxy for the OAI AUSF (Authentication Server Function). It generates DIDs using secp256k1 cryptography and registers them with the BCF (Blockchain Function).This is a DID (Decentralized Identifier) generation proxy for the OAI AUSF (Authentication Server Function). It generates DIDs using secp256k1 cryptography and registers them with the BCF (Blockchain Function).



## Features## Features



- Generates secp256k1 keypairs for DID generation- Generates secp256k1 keypairs for DID generation

- Creates DIDs in the format `did:oai5gc:<signature>`- Creates DIDs in the format `did:oai5gc:<signature>`

- Generates extended NF profiles with DID Documents- Generates extended NF profiles with DID Documents

- Registers NF profiles with BCF- Registers NF profiles with BCF

- Supports key persistence for consistent DID across restarts- Supports key persistence for consistent DID across restarts



## Architecture## Architecture



``````

┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐

│                 │       │                 │       │                 ││                 │       │                 │       │                 │

│   DID Proxy     │──────>│      BCF        │<──────│      NRF        ││   DID Proxy     │──────>│      BCF        │<──────│      NRF        │

│   (AUSF)        │       │                 │       │                 ││   (AUSF)        │       │                 │       │                 │

│                 │       │                 │       │                 ││                 │       │                 │       │                 │

└────────┬────────┘       └─────────────────┘       └─────────────────┘└────────┬────────┘       └─────────────────┘       └─────────────────┘

         │         │

         │  extended_ausf_profile.json         │  extended_ausf_profile.json

         v         v

┌─────────────────┐┌─────────────────┐

│                 ││                 │

│      AUSF       ││      AUSF       │

│                 ││                 │

└─────────────────┘└─────────────────┘

``````



## Building## Building



### Prerequisites### Prerequisites



- Go 1.21 or later- Go 1.21 or later



### Build Steps### Build Steps



```bash```bash

# Clone and navigate to did-proxy directory# Clone and navigate to did-proxy directory

cd src/did-proxycd src/did-proxy



# Build# Build

./build.sh./build.sh



# Or manually# Or manually

go build -o build/did-proxy .go build -o did-proxy .

``````



### Docker Build### Docker Build



```bash```bash

docker build -t oai-ausf-did-proxy:latest .docker build -t oai-ausf-did-proxy:latest .

``````



## Usage## Usage



### Command Line### Command Line



```bash```bash

# Generate DID and register with BCF# Generate DID and register with BCF

./build/did-proxy -config /usr/local/etc/oai/config.yaml./did-proxy --config /usr/local/etc/oai/config.yaml --nf-type ausf



# Specify custom key storage path# Generate DID only (no BCF registration)

./build/did-proxy -config /usr/local/etc/oai/config.yaml -keypath /usr/local/etc/oai/keys./did-proxy --config /usr/local/etc/oai/config.yaml --nf-type ausf --no-register

```

# Specify custom output path

./build/did-proxy -config /usr/local/etc/oai/config.yaml -output /usr/local/etc/oai/extended_ausf_profile.json### Command Line Options

```

| Option | Description | Default |

### Command Line Options|--------|-------------|---------|

| `--config` | Path to OAI config file | `/usr/local/etc/oai/config.yaml` |

| Option | Description | Default || `--nf-type` | Network Function type | `ausf` |

|--------|-------------|---------|| `--no-register` | Skip BCF registration | `false` |

| `-config` | Path to OAI config file | `/usr/local/etc/oai/config.yaml` |

| `-output` | Path to save extended NF profile | `/usr/local/etc/oai/extended_ausf_profile.json` |### Docker Compose

| `-keypath` | Path to key storage directory | `/usr/local/etc/oai/keys` |

```bash

### Docker Composedocker-compose up -d

```

```bash

docker-compose up -d## Configuration

```

The DID Proxy reads the OAI configuration file and uses the following settings:

## Configuration

```yaml

The DID Proxy reads the OAI configuration file and uses the following settings:# config.yaml

register_bcf:

```yaml  general: yes  # Enable BCF registration

# config.yaml

register_bcf:extended_profile_path: /usr/local/etc/oai/extended_ausf_profile.json

  general: yes  # Enable BCF registration

nfs:

extended_profile_path: /usr/local/etc/oai/extended_ausf_profile.json  bcf:

key_store_path: /usr/local/etc/oai/keys    host: oai-bcf

    sbi:

ausf:      port: 8080

  ausf_name: oai-ausf      api_version: v1

  nf_instance_id:  # Auto-generated if not set```



nfs:## Output Files

  ausf:

    host: oai-ausf### Extended NF Profile

    sbi:

      port: 8095The DID Proxy generates an extended NF profile at the configured path (default: `/usr/local/etc/oai/extended_ausf_profile.json`):

      api_version: v1

  bcf:```json

    host: oai-bcf{

    sbi:  "nfInstanceId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",

      port: 8089  "nfType": "AUSF",

      api_version: v1  "nfStatus": "REGISTERED",

```  "did": "did:oai5gc:304402...",

  "didDocument": {

## Output Files    "@context": [

      "https://www.w3.org/ns/did/v1",

### Extended NF Profile      "https://w3id.org/security/suites/secp256k1-2019/v1"

    ],

The DID Proxy generates an extended NF profile at the configured path (default: `/usr/local/etc/oai/extended_ausf_profile.json`):    "id": "did:oai5gc:304402...",

    "verificationMethod": [

```json      {

{        "id": "did:oai5gc:304402...#keys-1",

  "nfInstanceId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",        "type": "EcdsaSecp256k1VerificationKey2019",

  "nfType": "AUSF",        "controller": "did:oai5gc:304402...",

  "nfStatus": "REGISTERED",        "publicKeyMultibase": "zQ3shX..."

  "did": "did:oai5gc:304402...",      }

  "didDocument": {    ],

    "@context": [    "authentication": ["did:oai5gc:304402...#keys-1"],

      "https://www.w3.org/ns/did/v1",    "assertionMethod": ["did:oai5gc:304402...#keys-1"]

      "https://w3id.org/security/suites/secp256k1-2019/v1"  },

    ],  "created": "2024-01-01T00:00:00Z",

    "id": "did:oai5gc:304402...",  "modified": "2024-01-01T00:00:00Z"

    "verificationMethod": [}

      {```

        "id": "did:oai5gc:304402...#key-1",

        "type": "EcdsaSecp256k1VerificationKey2019",### Key Storage

        "controller": "did:oai5gc:304402...",

        "publicKeyMultibase": "zQ3shX..."Keys are stored at `/usr/local/etc/oai/keys/ausf_keys.json`:

      }

    ],```json

    "authentication": ["did:oai5gc:304402...#key-1"],{

    "assertionMethod": ["did:oai5gc:304402...#key-1"]  "nfInstanceId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",

  },  "privateKeyHex": "...",

  "created": "2024-01-01T00:00:00Z",  "publicKeyHex": "...",

  "modified": "2024-01-01T00:00:00Z"  "did": "did:oai5gc:..."

}}

``````



### Key Storage## Integration with AUSF



Keys are stored at `/usr/local/etc/oai/keys/`:The AUSF C++ code reads the extended profile to:



- `{nfInstanceId}_private.hex` - Private key in hex format1. Use the same `nfInstanceId` for NRF registration

- `{nfInstanceId}_public.hex` - Public key in hex format2. Register with BCF using the DID information



## Integration with AUSFEnsure the DID Proxy runs before AUSF starts.



The AUSF C++ code reads the extended profile to:## License



1. Use the same `nfInstanceId` for NRF registrationSee the main OAI AUSF LICENSE file.

2. Register with BCF using the DID information

Ensure the DID Proxy runs before AUSF starts.

## License

See the main OAI AUSF LICENSE file.
