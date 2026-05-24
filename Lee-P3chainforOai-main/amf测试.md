NODE=http://127.0.0.1:8001
zhang@zhang:~/BCF$ TODAY=$(date -I)
D=$(jq -r '.did' /tmp/oai/extended_amf_profile.jsozhang@zhang:~/BCF$ AMF_DID=$(jq -r '.did' /tmp/oai/extended_amf_profile.json)
 \
  --data-urlencode "operatorDid=$AMF_DID" \
  --data-urlencode "operationType=NF_REGISTER" \
  --data-urlencode "startTime=$TODAY" \
  --data-urlencode "pageSize=5" | jqzhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   --data-urlencode "operatorDid=$AMF_DID" \
>   --data-urlencode "operationType=NF_REGISTER" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "NF_REGISTER-1779615985475876983-af6edec6-9a73-4aea-94af-e9ddf0d9ff36",
      "operator_did": "did:oai5gc:fddbed2c35266ab01e7aca05ccdf4e68:0429723f5149609c812044b69c04e41ac5ba1f5ba5c891db2c3291b4de3587b8d6a6816ed7f8d93ae75c12016b4d9e30aa4236861bda87455443282f4f88cb1a68",
      "operation_type": "NF_REGISTER",
      "target_object_id": "e855b760-ba4a-49ae-8ffb-9caf8b016cfe",
      "request_hash": "8f2f467674a5aa26c2b98473e6d4f4c2110bfd73fab4eb26be26da7996dcd69c",
      "result": "SUCCESS",
      "result_code": 201,
      "timestamp": "2026-05-24T09:46:20.684051307Z",
      "tx_hash": "4788e2819d946dc9188a2a21e58c0241daaea5e13652e48821e3fef82b1ed633",
      "related_tx_hash": "4645e5ac0e8edd47b8e1782abf3d76138641499c54d9afddd7045fc1a7485681",
      "resource_path": "/nbcf_management/v1/nf_instances/e855b760-ba4a-49ae-8ffb-9caf8b016cfe",
      "method": "PUT",
      "trace_id": "173d3180-cb6c-48e0-955e-cc8586c64563",
      "subject_did": "did:oai5gc:fddbed2c35266ab01e7aca05ccdf4e68:0429723f5149609c812044b69c04e41ac5ba1f5ba5c891db2c3291b4de3587b8d6a6816ed7f8d93ae75c12016b4d9e30aa4236861bda87455443282f4f88cb1a68",
      "evidence_level": "index",
      "metadata": {
        "is_update": "false",
        "nf_type": "AMF"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   --data-urlencode "operatorDid=$AMF_DID" \
>   --data-urlencode "operationType=AUTH_VERIFY" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "AUTH_VERIFY-1779615985501197455-778102f4-5410-4d1d-8dbc-9da1af21787e",
      "operator_did": "did:oai5gc:fddbed2c35266ab01e7aca05ccdf4e68:0429723f5149609c812044b69c04e41ac5ba1f5ba5c891db2c3291b4de3587b8d6a6816ed7f8d93ae75c12016b4d9e30aa4236861bda87455443282f4f88cb1a68",
      "operation_type": "AUTH_VERIFY",
      "target_object_id": "239556a1-462b-4909-b15d-e18aee27dba8",
      "request_hash": "5aa89dadbce8f9cac6d784d41b85627f7ae8050e5d92ab2a7b542224343f1512",
      "result": "SUCCESS",
      "result_code": 200,
      "timestamp": "2026-05-24T09:46:25.478958552Z",
      "tx_hash": "975f5dc220595f055ca946395301adacdedda59c973cf6702828e0489ca0f611",
      "resource_path": "/nbcf_auth/v1/auth/verify",
      "method": "POST",
      "trace_id": "06e5bfc2-5113-4a4c-a5eb-9fb3ddee44c3",
      "subject_did": "did:oai5gc:fddbed2c35266ab01e7aca05ccdf4e68:0429723f5149609c812044b69c04e41ac5ba1f5ba5c891db2c3291b4de3587b8d6a6816ed7f8d93ae75c12016b4d9e30aa4236861bda87455443282f4f88cb1a68",
      "evidence_level": "index",
      "metadata": {
        "nf_instance_id": "e855b760-ba4a-49ae-8ffb-9caf8b016cfe",
        "nf_type": "AMF",
        "verify_mode": "bcf_auth"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   --data-urlencode "operatorDid=$AMF_DID" \
>   --data-urlencode "operationType=SUBSCRIPTION_CREATE" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "SUBSCRIPTION_CREATE-1779615999267907772-eb1976d3-41f5-440e-987a-f35582a1fd29",
      "operator_did": "did:oai5gc:fddbed2c35266ab01e7aca05ccdf4e68:0429723f5149609c812044b69c04e41ac5ba1f5ba5c891db2c3291b4de3587b8d6a6816ed7f8d93ae75c12016b4d9e30aa4236861bda87455443282f4f88cb1a68",
      "operation_type": "SUBSCRIPTION_CREATE",
      "target_object_id": "sub-1779615996528440366",
      "request_hash": "d612bb6071e75f32944a1a2fb4185e432ad8d0d2f2c3890332db9f39588205a7",
      "result": "SUCCESS",
      "result_code": 201,
      "timestamp": "2026-05-24T09:46:36.528219441Z",
      "tx_hash": "15f3b29800ae1599708d07fbb928890289aa4aa42d258a01a6cb893316f5c503",
      "related_tx_hash": "14f9aa8c7603153a087939a2c42dcfe263c64e3d1f610b9a0439dc1be2fb8762",
      "resource_path": "/nbcf_management/v1/subscriptions",
      "method": "POST",
      "trace_id": "dc46266d-9649-407d-bef1-bab6e9ea07d1",
      "subject_did": "did:oai5gc:fddbed2c35266ab01e7aca05ccdf4e68:0429723f5149609c812044b69c04e41ac5ba1f5ba5c891db2c3291b4de3587b8d6a6816ed7f8d93ae75c12016b4d9e30aa4236861bda87455443282f4f88cb1a68",
      "evidence_level": "index",
      "metadata": {
        "target_did": "",
        "target_nf_type": "AUSF"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_audit/v1/session-digests" \
>   --data-urlencode "did=$AMF_DID" \
>   --data-urlencode "purpose=amf-real-audit-check" | jq
{
  "sessionDigests": [
    {
      "session_id": "lifecycle:AMF:e855b760-ba4a-49ae-8ffb-9caf8b016cfe",
      "subject_did": "did:oai5gc:fddbed2c35266ab01e7aca05ccdf4e68:0429723f5149609c812044b69c04e41ac5ba1f5ba5c891db2c3291b4de3587b8d6a6816ed7f8d93ae75c12016b4d9e30aa4236861bda87455443282f4f88cb1a68",
      "peer_did": "BCF",
      "subject_nf_type": "AMF",
      "peer_nf_type": "BCF",
      "digest_hash": "a06cf0184a92afe91aa0c6b40412fe0100d548b88c09babd1b6e854e2674fecc",
      "event_count": 4,
      "summary_seq": 1,
      "stage": "bcf_auth_completed",
      "summary_type": "checkpoint",
      "timestamp": 1779615985502,
      "anchored_at": "2026-05-24T09:46:25.503020072Z",
      "anchor_tx_hash": "888bd47d2661a375e068cb10d1e71abf0539221627140f31f2b02ac16146c7a5",
      "evidence_level": "tier1",
      "token_fingerprint": "075b7c7a88a99304"
    }
  ]
}
zhang@zhang:~/BCF$ AMF_SESSION_ID=$(curl -sG "$NODE/nbcf_audit/v1/session-digests" \
>   --data-urlencode "did=$AMF_DID" \
>   --data-urlencode "purpose=amf-real-audit-check" | jq -r '.sessionDigests[0].session_id')
GEST_HASH=$(curl -sG "$NODE/nbcf_audit/v1/session-digests" \
  --data-urlencode "did=$AMF_DID" \
  --data-urlencode "purpose=amf-real-audit-check" | jq -r '.sessionDigests[0].digest_hash')

curl -s -Xzhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ AMF_DIGEST_HASH=$(curl -sG "$NODE/nbcf_audit/v1/session-digests" \
>   --data-urlencode "did=$AMF_DID" \
>   --data-urlencode "purpose=amf-real-audit-check" | jq -r '.sessionDigests[0].digest_hash')
-Type: application/json" \
  -d "$(jq -n \
    --arg sid "$AMF_SESSION_ID" \
    --arg hash "$AMF_DIGEST_HASH" \
    '{session_id:$sid, claimed_digest_hash:$hash, summary_seq:1}')" | jqzhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ curl -s -X POST "$NODE/nbcf_audit/v1/verify" \
>   -H "Content-Type: application/json" \
>   -d "$(jq -n \
>     --arg sid "$AMF_SESSION_ID" \
>     --arg hash "$AMF_DIGEST_HASH" \
>     '{session_id:$sid, claimed_digest_hash:$hash, summary_seq:1}')" | jq
{
  "session_id": "lifecycle:AMF:e855b760-ba4a-49ae-8ffb-9caf8b016cfe",
  "summary_seq": 1,
  "verified": true,
  "on_chain_digest_hash": "a06cf0184a92afe91aa0c6b40412fe0100d548b88c09babd1b6e854e2674fecc",
  "anchor_tx_hash": "888bd47d2661a375e068cb10d1e71abf0539221627140f31f2b02ac16146c7a5",
  "claimed_digest_hash": "a06cf0184a92afe91aa0c6b40412fe0100d548b88c09babd1b6e854e2674fecc",
  "on_chain_event_count": 4,
  "on_chain_anchored_at": "2026-05-24T09:46:25.503020072Z",
  "on_chain_summary_type": "checkpoint"
}
zhang@zhang:~/BCF$ 