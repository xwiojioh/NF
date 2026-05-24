curl -i -X PUT "$NODE/nbcf_management/v1/nf_instances/$NF_ID" \
>   -H "Content-Type: application/json" \
>   -d "$REG_BODY"
HTTP/1.1 201 Created
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Content-Type, Content-Length, Token, Authorization, X-Session-ID, X-Interaction-ID, X-Subject-DID, X-Peer-DID, X-Subject-NF-Type, X-Peer-NF-Type
Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PATCH, PUT
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Access-Control-Allow-Headers, Token
Content-Type: application/json; charset=utf-8
Date: Sun, 24 May 2026 05:58:43 GMT
Content-Length: 122

{"did":"did:test:nf-audit:20260524135632","nfInstanceId":"nf-audit-20260524135632","nfStatus":"REGISTERED","nfType":"AMF"}zhang@zhang:~/BCF$ sleep 3
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=NF_REGISTER" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "NF_REGISTER-1779602323086547158-894fc53b-18f1-43c3-9f89-401220469f21",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "NF_REGISTER",
      "target_object_id": "nf-audit-20260524135632",
      "request_hash": "3804cd334d17f0f949e022b3510fcc97951235c5c852d2cb868a6b89f62643ea",
      "result": "SUCCESS",
      "result_code": 201,
      "timestamp": "2026-05-24T05:58:34.168753053Z",
      "tx_hash": "1efdbe3062cbd4f4ac2efb4ccd041426de1b876c07956abe5630155bc016a599",
      "related_tx_hash": "285be0a53495d5f5170799f864b4956bd274eed55943170b78026f563b0e8b70",
      "resource_path": "/nbcf_management/v1/nf_instances/nf-audit-20260524135632",
      "method": "PUT",
      "trace_id": "99a14552-bdd4-446d-a25b-a7070193bbc3",
      "subject_did": "did:test:nf-audit:20260524135632",
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
zhang@zhang:~/BCF$ CHAL=$(curl -s -X POST "$NODE/nbcf_auth/v1/challenges" \
>   -H "Content-Type: application/json" \
>   -d "$(jq -n --arg did "$DID" --arg nfid "$NF_ID" '{did:$did,nfInstanceId:$nfid}')")
qzhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ echo "$CHAL" | jq
{
  "did": "did:test:nf-audit:20260524135632",
  "challengeId": "chal-8c68d69cc64e3d78",
  "nonce": "d78ccfa1ae73ab05dd69f08d249a87a3",
  "issuedAt": "2026-05-24T06:00:19Z",
  "expiresAt": "2026-05-24T06:05:19Z",
  "status": "PENDING"
}
zhang@zhang:~/BCF$ CHALLENGE_ID=$(echo "$CHAL" | jq -r '.challengeId')
D}:${CHALLENGE_ID}:${NONCE}"

echo "$MSG"zhang@zhang:~/BCF$ NONCE=$(echo "$CHAL" | jq -r '.nonce')
zhang@zhang:~/BCF$ MSG="${DID}:${CHALLENGE_ID}:${NONCE}"
zhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ echo "$MSG"
did:test:nf-audit:20260524135632:chal-8c68d69cc64e3d78:d78ccfa1ae73ab05dd69f08d249a87a3
zhang@zhang:~/BCF$ SIG=$(curl -s -X POST "$NODE/dper/signaturereturn" \
>   --data-urlencode "message=$MSG" | jq -r '.signature')
zhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ echo "$SIG"
6b71e8a170ebc3fbe10d1cc69ab2039921ce6e8bddc78db1ff1b0e16c561c8f4269f9864d8fa6351e176924e8e310236103d203dd4ce1712db8e97310e2744d400
zhang@zhang:~/BCF$ AUTH=$(curl -s -X POST "$NODE/nbcf_auth/v1/verify" \
>   -H "Content-Type: application/json" \
>   -d "$(jq -n \
>     --arg did "$DID" \
>     --arg cid "$CHALLENGE_ID" \
>     --arg nonce "$NONCE" \
>     --arg sig "$SIG" \
>     '{did:$did,challengeId:$cid,nonce:$nonce,signature:$sig}')")
zhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ echo "$AUTH" | jq
{
  "authStatus": "AUTHENTICATED",
  "challengeId": "chal-8c68d69cc64e3d78",
  "did": "did:test:nf-audit:20260524135632",
  "expiresIn": 3600,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJkaWQ6dGVzdDpuZi1hdWRpdDoyMDI2MDUyNDEzNTYzMiIsInBlcm1pc3Npb25zIjpbInNlcnZpY2VfZGlzY292ZXJ5IiwiYXVkaXRfcmVhZCIsImF1ZGl0X2FuY2hvciIsInN1YnNjcmlwdGlvbl9jcmVhdGUiLCJzdWJzY3JpcHRpb25fbWFuYWdlIiwic3Vic2NyaXB0aW9uX2RlbGV0ZSJdLCJpc3MiOiJwM2NoYWluLWJjZiIsInN1YiI6ImRpZDp0ZXN0Om5mLWF1ZGl0OjIwMjYwNTI0MTM1NjMyIiwiZXhwIjoxNzc5NjA2MTk1LCJuYmYiOjE3Nzk2MDI1OTUsImlhdCI6MTc3OTYwMjU5NSwianRpIjoiZDY4YzNkNjYtODA2Mi00NWZlLThhNDUtOGM5NTEwNGRmZDg5In0.ic0gJQgPSWoGAkid9vdSlcvZJOWPgWoUDhRS1Yz1o6o",
  "tokenType": "Bearer"
}
zhang@zhang:~/BCF$ TOKEN=$(echo "$AUTH" | jq -r '.token')
EN:0:40}..."zhang@zhang:~/BCF$ echo "${TOKEN:0:40}..."
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...
zhang@zhang:~/BCF$ sleep 3
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=AUTH_VERIFY" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "AUTH_VERIFY-1779602595311198820-7818385b-745e-48a4-b0e5-d25fc20afc51",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "AUTH_VERIFY",
      "target_object_id": "chal-8c68d69cc64e3d78",
      "request_hash": "a515853fe25ff27e3c4ac7166539be8800132896ab47ae494674275050a1676d",
      "result": "SUCCESS",
      "result_code": 200,
      "timestamp": "2026-05-24T06:03:15.306102674Z",
      "tx_hash": "ccc72d2828c381ef73aebb810a7452d0895129ed1d73cc2a7a6af57041d7086a",
      "resource_path": "/nbcf_auth/v1/verify",
      "method": "POST",
      "trace_id": "12f8f449-d1bf-4f85-bda5-f0edbc7c7e35",
      "subject_did": "did:test:nf-audit:20260524135632",
      "evidence_level": "index",
      "metadata": {
        "token_id": "tok-1c796fbeb16f34f7",
        "verify_mode": "challenge"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ AUTH_AID=$(curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=AUTH_VERIFY" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=1" | jq -r '.auditLogs[0].audit_id')
s "$NODE/nbcf_management/v1/audit-logs/$AUTH_AID" \
  -H "Authorization: Bearer $TOKEN" \
  | jq -e 'tostring | test("signature|nonce") | not'zhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ curl -s "$NODE/nbcf_management/v1/audit-logs/$AUTH_AID" \
>   -H "Authorization: Bearer $TOKEN" \
>   | jq -e 'tostring | test("signature|nonce") | not'
true
zhang@zhang:~/BCF$ curl -sG "$PEER/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=AUTH_VERIFY" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "AUTH_VERIFY-1779602595311198820-7818385b-745e-48a4-b0e5-d25fc20afc51",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "AUTH_VERIFY",
      "target_object_id": "chal-8c68d69cc64e3d78",
      "request_hash": "a515853fe25ff27e3c4ac7166539be8800132896ab47ae494674275050a1676d",
      "result": "SUCCESS",
      "result_code": 200,
      "timestamp": "2026-05-24T06:03:15.306102674Z",
      "tx_hash": "ccc72d2828c381ef73aebb810a7452d0895129ed1d73cc2a7a6af57041d7086a",
      "resource_path": "/nbcf_auth/v1/verify",
      "method": "POST",
      "trace_id": "12f8f449-d1bf-4f85-bda5-f0edbc7c7e35",
      "subject_did": "did:test:nf-audit:20260524135632",
      "evidence_level": "index",
      "metadata": {
        "token_id": "tok-1c796fbeb16f34f7",
        "verify_mode": "challenge"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_discovery/v1/nf_instances" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "target-nf-type=AMF" | jq
{
  "nfInstances": [
    {
      "did": "did:test:nf-audit:20260524135632",
      "didDocument": {
        "id": "did:test:nf-audit:20260524135632",
        "verificationMethod": [
          {
            "blockchainAccountId": "0xa2891605a71abc7eb7aebb33edb299bb36f4d4a1",
            "controller": "did:test:nf-audit:20260524135632",
            "id": "did:test:nf-audit:20260524135632#key-1",
            "type": "EcdsaSecp256k1VerificationKey2019"
          }
        ]
      },
      "nfProfile": {
        "capacity": 100,
        "heartBeatTimer": 50,
        "nfInstanceId": "nf-audit-20260524135632",
        "nfStatus": "REGISTERED",
        "nfType": "AMF",
        "perPlmnSnssaiList": null,
        "plmnList": null,
        "priority": 1,
        "recoveryTime": "",
        "sNssais": null
      },
      "registeredAt": "2026-05-24T05:58:34Z",
      "updatedAt": "2026-05-24T05:58:34Z"
    }
  ]
}
zhang@zhang:~/BCF$ sleep 3
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=DISCOVERY" \
>   --data-urlencode "targetObjectId=AMF" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "DISCOVERY-1779602975250675645-2d90835b-84de-4f95-83d6-ab0e83357cd7",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "DISCOVERY",
      "target_object_id": "AMF",
      "request_hash": "cb27b02b2f22c592c647b74884a985d053367276908644ae49ad4b35b2115529",
      "result": "SUCCESS",
      "result_code": 200,
      "timestamp": "2026-05-24T06:09:35.248873935Z",
      "tx_hash": "ffb6232a7263f22e7d3d0f3bcb112def2027388d2fe67c419310c636de949190",
      "resource_path": "/nbcf_discovery/v1/nf_instances",
      "method": "GET",
      "trace_id": "564db51c-52c8-4d69-9cad-44b740423860",
      "subject_did": "did:test:nf-audit:20260524135632",
      "evidence_level": "index",
      "token_fingerprint": "bc9e7d18c1c88201",
      "metadata": {
        "result_count": "1",
        "target_nf_type": "AMF"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ SUB=$(curl -s -X POST "$NODE/nbcf_management/v1/subscriptions" \
>   -H "Authorization: Bearer $TOKEN" \
>   -H "Content-Type: application/json" \
>   -d "$(jq -n --arg did "$DID" '{
>     subscriberDid:$did,
>     targetNfType:"AMF",
>     callbackUrl:"http://127.0.0.1:9999/callback",
>     eventTypes:["NF_REGISTERED","NF_DEREGISTERED"]
>   }')")
qzhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ echo "$SUB" | jq
{
  "notification_transport": "auto",
  "subscription_id": "sub-1779603223538361368",
  "success": true,
  "target_nf_list": [
    {
      "capacity": 100,
      "did": "did:test:nf-audit:20260524135632",
      "didDocument": {
        "id": "did:test:nf-audit:20260524135632",
        "verificationMethod": [
          {
            "blockchainAccountId": "0xa2891605a71abc7eb7aebb33edb299bb36f4d4a1",
            "controller": "did:test:nf-audit:20260524135632",
            "id": "did:test:nf-audit:20260524135632#key-1",
            "type": "EcdsaSecp256k1VerificationKey2019"
          }
        ]
      },
      "heartBeatTimer": 50,
      "lastUpdateTime": "2026-05-24T05:58:34Z",
      "nfInstanceId": "nf-audit-20260524135632",
      "nfStatus": "REGISTERED",
      "nfType": "AMF",
      "perPlmnSnssaiList": null,
      "plmnList": null,
      "priority": 1,
      "recoveryTime": "",
      "registrationTime": "2026-05-24T05:58:34Z",
      "sNssais": null
    }
  ]
}
zhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ SUB_ID=$(echo "$SUB" | jq -r '.subscription_id')
cho "$SUB_ID"
sleep 3zhang@zhang:~/BCF$ echo "$SUB_ID"
sub-1779603223538361368
zhang@zhang:~/BCF$ sleep 3
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=SUBSCRIPTION_CREATE" \
>   --data-urlencode "targetObjectId=$SUB_ID" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "SUBSCRIPTION_CREATE-1779603226261922029-58429823-a8f8-4e92-93b7-27dedb631b55",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "SUBSCRIPTION_CREATE",
      "target_object_id": "sub-1779603223538361368",
      "request_hash": "138a062dfcdd34fafac150372591fee232faa0e2d7a5dcfbc758028471155f48",
      "result": "SUCCESS",
      "result_code": 201,
      "timestamp": "2026-05-24T06:13:43.538138975Z",
      "tx_hash": "17837e917867090aa0dd1a38ee07d1898619e14a3ce323ac6c3feb5029067ecb",
      "related_tx_hash": "e427470fc1df1628461056cf7622a45ed1df736238ccd0235237e879e8f8acbb",
      "resource_path": "/nbcf_management/v1/subscriptions",
      "method": "POST",
      "trace_id": "133adc61-a45c-4577-9b96-aefd7918763c",
      "subject_did": "did:test:nf-audit:20260524135632",
      "evidence_level": "index",
      "token_fingerprint": "bc9e7d18c1c88201",
      "metadata": {
        "target_did": "",
        "target_nf_type": "AMF"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/subscriptions" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "subscriber-did=$DID" | jq
{
  "subscriptions": [
    {
      "callbackUrl": "http://127.0.0.1:9999/callback",
      "createdAt": "2026-05-24T14:13:43+08:00",
      "eventTypes": [
        "NF_REGISTERED",
        "NF_DEREGISTERED"
      ],
      "notification_transport": "auto",
      "notification_uri": "http://127.0.0.1:9999/callback",
      "status": "ACTIVE",
      "subscriberDid": "did:test:nf-audit:20260524135632",
      "subscriber_nf_did": "did:test:nf-audit:20260524135632",
      "subscriptionId": "sub-1779603223538361368",
      "subscription_id": "sub-1779603223538361368",
      "targetNfType": "AMF",
      "target_nf_type": "AMF",
      "updatedAt": "2026-05-24T14:13:43+08:00"
    }
  ]
}
zhang@zhang:~/BCF$ sleep 3
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=SUBSCRIPTION_QUERY" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "SUBSCRIPTION_QUERY-1779603531405451085-cd635a1e-2b89-44d0-89e0-84ce3d40d53e",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "SUBSCRIPTION_QUERY",
      "target_object_id": "did:test:nf-audit:20260524135632",
      "request_hash": "59e4522e3ccec2dd168e903cde20105793f0b0787d6be3610739930719f8bda7",
      "result": "SUCCESS",
      "result_code": 200,
      "timestamp": "2026-05-24T06:18:51.404449375Z",
      "tx_hash": "c229820abdf733c724a7abcd999d9d30f512110fcf10ad10c6aef877df687ed3",
      "resource_path": "/nbcf_management/v1/subscriptions",
      "method": "GET",
      "trace_id": "e25c12e0-1abd-4057-9b85-c5e7eb910658",
      "subject_did": "did:test:nf-audit:20260524135632",
      "evidence_level": "index",
      "token_fingerprint": "bc9e7d18c1c88201",
      "metadata": {
        "result_count": "1"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ QUERY_AID=$(curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=SUBSCRIPTION_QUERY" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=1" | jq -r '.auditLogs[0].audit_id')
ERY_AID" \
  -H "Authorization: Bearer $TOKEN" | jqzhang@zhang:~/BCF$ 
zhang@zhang:~/BCF$ curl -s "$NODE/nbcf_management/v1/audit-logs/$QUERY_AID" \
>   -H "Authorization: Bearer $TOKEN" | jq
{
  "audit_id": "SUBSCRIPTION_QUERY-1779603531405451085-cd635a1e-2b89-44d0-89e0-84ce3d40d53e",
  "operator_did": "did:test:nf-audit:20260524135632",
  "operation_type": "SUBSCRIPTION_QUERY",
  "target_object_id": "did:test:nf-audit:20260524135632",
  "request_hash": "59e4522e3ccec2dd168e903cde20105793f0b0787d6be3610739930719f8bda7",
  "result": "SUCCESS",
  "result_code": 200,
  "timestamp": "2026-05-24T06:18:51.404449375Z",
  "tx_hash": "c229820abdf733c724a7abcd999d9d30f512110fcf10ad10c6aef877df687ed3",
  "resource_path": "/nbcf_management/v1/subscriptions",
  "method": "GET",
  "trace_id": "e25c12e0-1abd-4057-9b85-c5e7eb910658",
  "subject_did": "did:test:nf-audit:20260524135632",
  "evidence_level": "index",
  "token_fingerprint": "bc9e7d18c1c88201",
  "metadata": {
    "result_count": "1"
  }
}
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "page=1" \
>   --data-urlencode "pageSize=2" | jq
{
  "auditLogs": [
    {
      "audit_id": "SUBSCRIPTION_QUERY-1779603531405451085-cd635a1e-2b89-44d0-89e0-84ce3d40d53e",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "SUBSCRIPTION_QUERY",
      "target_object_id": "did:test:nf-audit:20260524135632",
      "request_hash": "59e4522e3ccec2dd168e903cde20105793f0b0787d6be3610739930719f8bda7",
      "result": "SUCCESS",
      "result_code": 200,
      "timestamp": "2026-05-24T06:18:51.404449375Z",
      "tx_hash": "c229820abdf733c724a7abcd999d9d30f512110fcf10ad10c6aef877df687ed3",
      "resource_path": "/nbcf_management/v1/subscriptions",
      "method": "GET",
      "trace_id": "e25c12e0-1abd-4057-9b85-c5e7eb910658",
      "subject_did": "did:test:nf-audit:20260524135632",
      "evidence_level": "index",
      "token_fingerprint": "bc9e7d18c1c88201",
      "metadata": {
        "result_count": "1"
      }
    },
    {
      "audit_id": "SUBSCRIPTION_CREATE-1779603226261922029-58429823-a8f8-4e92-93b7-27dedb631b55",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "SUBSCRIPTION_CREATE",
      "target_object_id": "sub-1779603223538361368",
      "request_hash": "138a062dfcdd34fafac150372591fee232faa0e2d7a5dcfbc758028471155f48",
      "result": "SUCCESS",
      "result_code": 201,
      "timestamp": "2026-05-24T06:13:43.538138975Z",
      "tx_hash": "17837e917867090aa0dd1a38ee07d1898619e14a3ce323ac6c3feb5029067ecb",
      "related_tx_hash": "e427470fc1df1628461056cf7622a45ed1df736238ccd0235237e879e8f8acbb",
      "resource_path": "/nbcf_management/v1/subscriptions",
      "method": "POST",
      "trace_id": "133adc61-a45c-4577-9b96-aefd7918763c",
      "subject_did": "did:test:nf-audit:20260524135632",
      "evidence_level": "index",
      "token_fingerprint": "bc9e7d18c1c88201",
      "metadata": {
        "target_did": "",
        "target_nf_type": "AMF"
      }
    }
  ],
  "page": 1,
  "pageSize": 2,
  "total": 5
}
zhang@zhang:~/BCF$ curl -i -X DELETE -G "$NODE/nbcf_management/v1/nf_instances/$NF_ID" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "did=$DID"
HTTP/1.1 204 No Content
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Content-Type, Content-Length, Token, Authorization, X-Session-ID, X-Interaction-ID, X-Subject-DID, X-Peer-DID, X-Subject-NF-Type, X-Peer-NF-Type
Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PATCH, PUT
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Access-Control-Allow-Headers, Token
Date: Sun, 24 May 2026 09:01:10 GMT

zhang@zhang:~/BCF$ sleep 3
zhang@zhang:~/BCF$ curl -sG "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN" \
>   --data-urlencode "operatorDid=$DID" \
>   --data-urlencode "operationType=NF_DEREGISTER" \
>   --data-urlencode "startTime=$TODAY" \
>   --data-urlencode "pageSize=5" | jq
{
  "auditLogs": [
    {
      "audit_id": "NF_DEREGISTER-1779613270253626625-29f6dd29-0550-4517-8089-9cc3372e23b0",
      "operator_did": "did:test:nf-audit:20260524135632",
      "operation_type": "NF_DEREGISTER",
      "target_object_id": "nf-audit-20260524135632",
      "request_hash": "35357467623e042a988e47526ca8872ee33089892b6543b19aed04de3b714216",
      "result": "SUCCESS",
      "result_code": 204,
      "timestamp": "2026-05-24T09:01:10.25224886Z",
      "tx_hash": "9e5085674b47adced55b203d7db9a58e4c7e81de3e10e33459809159dda9b527",
      "related_tx_hash": "5c0aaaa2da58132bf6a64ac42c37e87d6e4c58247bc6d001bb93c32e93547988",
      "resource_path": "/nbcf_management/v1/nf_instances/nf-audit-20260524135632",
      "method": "DELETE",
      "trace_id": "ad8ec92f-2e8f-4924-8311-f891cce56221",
      "subject_did": "did:test:nf-audit:20260524135632",
      "evidence_level": "index",
      "token_fingerprint": "bc9e7d18c1c88201",
      "metadata": {
        "nf_type": "AMF"
      }
    }
  ],
  "page": 1,
  "pageSize": 5,
  "total": 1
}
zhang@zhang:~/BCF$ curl -i "$NODE/nbcf_management/v1/audit-logs" \
>   -H "Authorization: Bearer $TOKEN"
HTTP/1.1 400 Bad Request
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Content-Type, Content-Length, Token, Authorization, X-Session-ID, X-Interaction-ID, X-Subject-DID, X-Peer-DID, X-Subject-NF-Type, X-Peer-NF-Type
Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PATCH, PUT
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Access-Control-Allow-Headers, Token
Content-Type: application/json; charset=utf-8
Date: Sun, 24 May 2026 09:02:44 GMT
Content-Length: 99

{"code":400,"data":{"error":"audit query requires at least one filter"},"msg":"请求参数错误"}zhang@zhang:~/BCF$ 