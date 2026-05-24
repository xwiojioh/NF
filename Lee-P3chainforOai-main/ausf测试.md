 NODE=http://127.0.0.1:8001
zhang@zhang:~/BCF$ PEER=http://127.0.0.1:8004
zhang@zhang:~/BCF$ TODAY=$(date -I)
/oai/extended_ausf_profile.json)
AUSF_NF_ID=$(jq -zhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ AUSF_DID=$(jq -r '.did' /tmp/oai/extended_ausf_profile.json)
r '.nfInstanceId' /tmp/oai/extended_ausf_profile.json)

echo "$AUSF_DID"
echo "$AUSF_NF_ID"
echo "$TODAY"zhang@zhang:~/BCF$ AUSF_NF_ID=$(jq -r '.nfInstanceId' /tmp/oai/extended_ausf_profile.json)
zhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ echo "$AUSF_DID"
did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7aab01522a33bbfb33182ec7fd99331f4feb901d9b0af41109c97de0bf66787c81e6d63f562a0f863be82f26890dc5af4da8ea14161b59c63182eda330c
zhang@zhang:~/BCF$ echo "$AUSF_NF_ID"
9b051fd3-94d3-477e-a5b8-c9c6e828c904
zhang@zhang:~/BCF$ echo "$TODAY"
2026-05-24
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   --data-urlencode "operatorDid=$AUSF_DID" \
>   --data-urlencode "operationType=NF_REGISTER" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "NF_REGISTER-1779618912668561816-c05dbd07-47eb-4f78-aac1-6b5329d55dcf",
      "operator_did": "did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7aab01522a33bbfb33182ec7fd99331f4feb901d9b0af41109c97de0bf66787c81e6d63f562a0f863be82f26890dc5af4da8ea14161b59c63182eda330c",
      "operation_type": "NF_REGISTER",
      "target_object_id": "9b051fd3-94d3-477e-a5b8-c9c6e828c904",
      "request_hash": "ff49bab530626f8436fac70f0a2d1a39881de9a47a4b99ee5034b16f6336d851",
      "result": "SUCCESS",
      "result_code": 200,
      "timestamp": "2026-05-24T10:35:12.666410012Z",
      "tx_hash": "54c76964bb4e8fa4882bb6301c1d2d3ba28f37d2c9e78db397e2039440abf7b1",
      "related_tx_hash": "ee53bdb39c1db87bc8e4b0e9239f8bb37701ea0c2b6ac08ae4c93d3564c074d1",
      "resource_path": "/nbcf_management/v1/nf_instances/9b051fd3-94d3-477e-a5b8-c9c6e828c904",
      "method": "PUT",
      "trace_id": "bb29ebc8-5fb0-414d-87c4-72c03a797689",
      "subject_did": "did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7aab01522a33bbfb33182ec7fd99331f4feb901d9b0af41109c97de0bf66787c81e6d63f562a0f863be82f26890dc5af4da8ea14161b59c63182eda330c",
      "evidence_level": "index",
      "metadata": {
        "is_update": "true",
        "nf_type": "AUSF"
      }
    },
    {
      "audit_id": "NF_REGISTER-1779616861493150533-38f2cb83-aca5-45ba-b179-1eeadcfc20e2",
      "operator_did": "did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7aab01522a33bbfb33182ec7fd99331f4feb901d9b0af41109c97de0bf66787c81e6d63f562a0f863be82f26890dc5af4da8ea14161b59c63182eda330c",
      "operation_type": "NF_REGISTER",
      "target_object_id": "9b051fd3-94d3-477e-a5b8-c9c6e828c904",
      "request_hash": "117df990dae4a355428a61bebd8ada4219453f18ab896d7699e218dc6e888afa",
      "result": "SUCCESS",
      "result_code": 201,
      "timestamp": "2026-05-24T10:00:56.376810514Z",
      "tx_hash": "549d78218ce4ec37c82c1a9ae4c0f97fb72b57c71468d1f25ad4efc0e7ee07c2",
      "related_tx_hash": "3bdfeb442ba962915e1680eaf69ce92b8dd545e9233ff865d7ca041029b74ce3",
      "resource_path": "/nbcf_management/v1/nf_instances/9b051fd3-94d3-477e-a5b8-c9c6e828c904",
      "method": "PUT",
      "trace_id": "279564cc-0b4e-425c-9b3e-9877b21e9ed8",
      "subject_did": "did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7aab01522a33bbfb33182ec7fd99331f4feb901d9b0af41109c97de0bf66787c81e6d63f562a0f863be82f26890dc5af4da8ea14161b59c63182eda330c",
      "evidence_level": "index",
      "metadata": {
        "is_update": "false",
        "nf_type": "AUSF"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 2
}
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   --data-urlencode "operatorDid=$AUSF_DID" \
>   --data-urlencode "operationType=AUTH_VERIFY" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "AUTH_VERIFY-1779618912676983873-01fd3523-0e23-4885-b51c-4f706bfc42e9",
      "operator_did": "did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7aab01522a33bbfb33182ec7fd99331f4feb901d9b0af41109c97de0bf66787c81e6d63f562a0f863be82f26890dc5af4da8ea14161b59c63182eda330c",
      "operation_type": "AUTH_VERIFY",
      "target_object_id": "bdf7a914-03ab-4ee2-9805-7c16d726e559",
      "request_hash": "a276625093e8a7f16eb933dc766ed7d427ac9a589ac61f30680f959cc86ffd03",
      "result": "SUCCESS",
      "result_code": 200,
      "timestamp": "2026-05-24T10:35:12.671523742Z",
      "tx_hash": "33eeff4342c6d8fc3531964a71d853f3c1674394016f293ed9914575b953feab",
      "resource_path": "/nbcf_auth/v1/auth/verify",
      "method": "POST",
      "trace_id": "5a2947a0-1995-4ed0-8587-8915f06b05a9",
      "subject_did": "did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7aab01522a33bbfb33182ec7fd99331f4feb901d9b0af41109c97de0bf66787c81e6d63f562a0f863be82f26890dc5af4da8ea14161b59c63182eda330c",
      "evidence_level": "index",
      "metadata": {
        "nf_instance_id": "9b051fd3-94d3-477e-a5b8-c9c6e828c904",
        "nf_type": "AUSF",
        "verify_mode": "bcf_auth"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_audit/v1/session-digests" \
>   --data-urlencode "did=$AUSF_DID" \
>   --data-urlencode "purpose=ausf-real-audit-check" | jq
{
  "sessionDigests": [
    {
      "session_id": "lifecycle:AUSF:9b051fd3-94d3-477e-a5b8-c9c6e828c904",
      "subject_did": "did:oai5gc:f87deb45c7a61118f41ba3a967ff69f0:043a7bb7aab01522a33bbfb33182ec7fd99331f4feb901d9b0af41109c97de0bf66787c81e6d63f562a0f863be82f26890dc5af4da8ea14161b59c63182eda330c",
      "peer_did": "BCF",
      "subject_nf_type": "AUSF",
      "peer_nf_type": "BCF",
      "digest_hash": "68dcaab57625b91f9856261b8d3e946994703ed355f795a078caa8b1dbcd19c1",
      "event_count": 4,
      "summary_seq": 1,
      "stage": "bcf_auth_completed",
      "summary_type": "checkpoint",
      "timestamp": 1779618912677,
      "anchored_at": "2026-05-24T10:35:12.678529145Z",
      "anchor_tx_hash": "ac2ab1bf225d8fb5a21b38a5266aa0a47f18c130f62c978927ec91e0a6aa5c6b",
      "evidence_level": "tier1",
      "token_fingerprint": "9863907f738371d1"
    }
  ]
}
zhang@zhang:~/BCF$ AUSF_SESSION_ID=$(curl -sG "$NODE/nbcf_audit/v1/session-digests" \
>   --data-urlencode "did=$AUSF_DID" \
>   --data-urlencode "purpose=ausf-real-audit-check" | jq -r '.sessionDigests[0].session_id')
F_DIGEST_HASH=$(curl -sG "$NODE/nbcf_audit/v1/session-digests" \
  --data-urlencode "did=$AUSF_DID" \
  --data-urlencode "purpose=ausf-real-audit-check" | jq -r '.sessionDigests[0].digest_hash')

curlzhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ AUSF_DIGEST_HASH=$(curl -sG "$NODE/nbcf_audit/v1/session-digests" \
>   --data-urlencode "did=$AUSF_DID" \
>   --data-urlencode "purpose=ausf-real-audit-check" | jq -r '.sessionDigests[0].digest_hash')
 -s -X POST "$NODE/nbcf_audit/v1/verify" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg sid "$AUSF_SESSION_ID" \
    --arg hash "$AUSF_DIGEST_HASH" \
    '{session_id:$sid, claimed_digest_hash:$hash, summary_seq:1}')" | jqzhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ curl -s -X POST "$NODE/nbcf_audit/v1/verify" \
>   -H "Content-Type: application/json" \
>   -d "$(jq -n \
>     --arg sid "$AUSF_SESSION_ID" \
>     --arg hash "$AUSF_DIGEST_HASH" \
>     '{session_id:$sid, claimed_digest_hash:$hash, summary_seq:1}')" | jq
{
  "session_id": "lifecycle:AUSF:9b051fd3-94d3-477e-a5b8-c9c6e828c904",
  "summary_seq": 1,
  "verified": true,
  "on_chain_digest_hash": "68dcaab57625b91f9856261b8d3e946994703ed355f795a078caa8b1dbcd19c1",
  "anchor_tx_hash": "ac2ab1bf225d8fb5a21b38a5266aa0a47f18c130f62c978927ec91e0a6aa5c6b",
  "claimed_digest_hash": "68dcaab57625b91f9856261b8d3e946994703ed355f795a078caa8b1dbcd19c1",
  "on_chain_event_count": 4,
  "on_chain_anchored_at": "2026-05-24T10:35:12.678529145Z",
  "on_chain_summary_type": "checkpoint"
}
zhang@zhang:~/BCF$ 