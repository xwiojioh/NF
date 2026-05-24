# DID Proxy for OAI 5GC

DID Proxy is a tool that generates Decentralized Identifiers (DIDs) for OAI 5G Core Network Functions. It creates an Extended NF Profile containing DID and DID Document, which NFs (like AMF) read to register with BCF (Blockchain Function).

## Architecture

```
  ┌─────────────────────┐                  ┌─────────────────────┐
  │  DID Proxy (Go)     │                  │      AMF (C++)      │
  │                     │                  │                     │
  │ 1. Read config.yaml │                  │ 1. Read config.yaml │
  │ 2. Generate Profile │                  │ 2. Check BCF enable │
  │ 3. Generate DID     │  ──file write──► │ 3. Read ext profile │
  │ 4. Create Extended  │                  │ 4. Register to BCF  │
  │    NF Profile       │                  │                     │
  │ 5. Save to file     │                  │                     │
  └─────────────────────┘                  └──────────┬──────────┘
                                                      │ HTTP PUT
  File: /usr/local/etc/oai/extended_amf_profile.json  ▼
                                           ┌─────────────────────┐
                                           │        BCF          │
                                           └─────────────────────┘
```

## File Naming Convention

Extended profile files are named by NF type for multi-NF deployment:
- AMF: `/usr/local/etc/oai/extended_amf_profile.json`
- SMF: `/usr/local/etc/oai/extended_smf_profile.json`
- UDM: `/usr/local/etc/oai/extended_udm_profile.json`
- etc.

## Configuration

Add the following to your config.yaml (following OAI standard patterns):

```yaml
# Extended profile path (top-level config)
# Use NF-specific filename
extended_profile_path: /usr/local/etc/oai/extended_amf_profile.json

# Enable BCF registration (same format as register_nf)
register_bcf:
  general: yes

# In nfs section (same format as other NFs like nrf, smf, etc.)
nfs:
  bcf:
    host: oai-bcf
    sbi:
      port: 8080
      api_version: v1
      interface_name: eth0
```

The BCF URI is automatically constructed from the host/sbi configuration:
- Format: `http://<host>:<port>/nbcf_nfm/<api_version>/nf_instances/<nf_instance_id>`
- Example: `http://oai-bcf:8080/nbcf_nfm/v1/nf_instances/amf-1234`

## Usage

```bash
# Run DID Proxy before AMF
./did-proxy -config /path/to/config.yaml
```

## Build

```bash
cd src/did-proxy
go build -o did-proxy .
```
