curl -s http://127.0.0.1:8004/block/getRecentTransactions/10 | jq .
{
  "code": 200,
  "data": {
    "transactionList": [
      {
        "txID": "a23f967d90f388f35aab881990682be21c2e30ce05f8f36ef25a06a423e5b450",
        "sender": "9139989c02cfb456823677af544ac7c72d4bcba3",
        "version": "0000000000000000000000000000000000000000000000000000000000000000",
        "signature": "19hpEHn+s/G/TKYpaIy9FYEBwDaNoS4m+u3jSZSUdpoLBxPcE1q8KFr920EU2beCEIEzCCkbfyiwXnu0O1K4ogA=",
        "contract": "014449443a3a535045435452554d3a3a54524144",
        "function": "016a3098ad07c632100462980de14136e20117ab",
        "args": [
          "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
          "{\"nfProfile\":{\"amfInfo\":{\"amfRegionId\":\"01\",\"amfSetId\":\"001\",\"guamiList\":[{\"amfId\":\"0100101\",\"plmnId\":{\"mcc\":\"208\",\"mnc\":\"95\"}},{\"amfId\":\"0100101\",\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}]},\"capacity\":30,\"fqdn\":\"127.0.0.1\",\"heartBeatTimer\":50,\"nfInstanceId\":\"2a49571a-bbf0-4b23-bc6b-284657095543\",\"nfServices\":[{\"ipEndPoints\":[{\"ipv4Address\":\"127.0.0.1\",\"port\":8080,\"transport\":\"TCP\"}],\"nfServiceStatus\":\"REGISTERED\",\"scheme\":\"http\",\"serviceInstanceId\":\"2a49571a-bbf0-4b23-bc6b-284657095543\",\"serviceName\":\"namf-comm\",\"versions\":[{\"apiFullVersion\":\"1.0.0\",\"apiVersionInUri\":\"v1\"}]},{\"ipEndPoints\":[{\"ipv4Address\":\"127.0.0.1\",\"port\":8080,\"transport\":\"TCP\"}],\"nfServiceStatus\":\"REGISTERED\",\"scheme\":\"http\",\"serviceInstanceId\":\"namf-evts\",\"serviceName\":\"namf-evts\",\"versions\":[{\"apiFullVersion\":\"1.0.0\",\"apiVersionInUri\":\"v1\"}]}],\"nfStatus\":\"REGISTERED\",\"nfType\":\"AMF\",\"perPlmnSnssaiList\":[{\"plmnId\":{\"mcc\":\"208\",\"mnc\":\"95\"},\"sNssaiList\":[{\"sst\":1},{\"sd\":\"000001\",\"sst\":1},{\"sd\":\"00007B\",\"sst\":222}]}],\"plmnList\":[{\"mcc\":\"208\",\"mnc\":\"95\"}],\"priority\":1,\"recoveryTime\":\"2026-05-12T13:43:36Z\",\"sNssais\":[{\"sst\":1},{\"sd\":\"000001\",\"sst\":1},{\"sd\":\"00007B\",\"sst\":222}]},\"didDocument\":{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/suites/secp256k1-2019/v1\"],\"assertionMethod\":[\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1\"],\"authentication\":[\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1\"],\"controller\":\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606\",\"created\":\"2026-05-12T13:43:36Z\",\"id\":\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606\",\"updated\":\"2026-05-12T13:43:36Z\",\"verificationMethod\":[{\"controller\":\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606\",\"id\":\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1\",\"publicKeyMultibase\":\"zpg3FRVCaspCb4GcKHg9uwf1wjY5GvHH7te2wvo48yFyV\",\"type\":\"EcdsaSecp256k1VerificationKey2019\"}]},\"registeredAt\":\"2026-05-12T13:43:44Z\",\"updatedAt\":\"2026-05-12T13:43:44Z\"}"
        ],
        "receipt": {
          "valid": 1,
          "result": [
            "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
            "OK"
          ]
        }
      }
    ],
    "reqTxCount": 10,
    "resTxCount": 1
  },
  "msg": "ok"
}
zhang@zhang:~/BCF$ curl -s http://127.0.0.1:8004/block/getRecentTransactions/10 \
>   | jq '.data.transactionList[] | {txID, contract, function, args, receipt}'
{
  "txID": "a23f967d90f388f35aab881990682be21c2e30ce05f8f36ef25a06a423e5b450",
  "contract": "014449443a3a535045435452554d3a3a54524144",
  "function": "016a3098ad07c632100462980de14136e20117ab",
  "args": [
    "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
    "{\"nfProfile\":{\"amfInfo\":{\"amfRegionId\":\"01\",\"amfSetId\":\"001\",\"guamiList\":[{\"amfId\":\"0100101\",\"plmnId\":{\"mcc\":\"208\",\"mnc\":\"95\"}},{\"amfId\":\"0100101\",\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}]},\"capacity\":30,\"fqdn\":\"127.0.0.1\",\"heartBeatTimer\":50,\"nfInstanceId\":\"2a49571a-bbf0-4b23-bc6b-284657095543\",\"nfServices\":[{\"ipEndPoints\":[{\"ipv4Address\":\"127.0.0.1\",\"port\":8080,\"transport\":\"TCP\"}],\"nfServiceStatus\":\"REGISTERED\",\"scheme\":\"http\",\"serviceInstanceId\":\"2a49571a-bbf0-4b23-bc6b-284657095543\",\"serviceName\":\"namf-comm\",\"versions\":[{\"apiFullVersion\":\"1.0.0\",\"apiVersionInUri\":\"v1\"}]},{\"ipEndPoints\":[{\"ipv4Address\":\"127.0.0.1\",\"port\":8080,\"transport\":\"TCP\"}],\"nfServiceStatus\":\"REGISTERED\",\"scheme\":\"http\",\"serviceInstanceId\":\"namf-evts\",\"serviceName\":\"namf-evts\",\"versions\":[{\"apiFullVersion\":\"1.0.0\",\"apiVersionInUri\":\"v1\"}]}],\"nfStatus\":\"REGISTERED\",\"nfType\":\"AMF\",\"perPlmnSnssaiList\":[{\"plmnId\":{\"mcc\":\"208\",\"mnc\":\"95\"},\"sNssaiList\":[{\"sst\":1},{\"sd\":\"000001\",\"sst\":1},{\"sd\":\"00007B\",\"sst\":222}]}],\"plmnList\":[{\"mcc\":\"208\",\"mnc\":\"95\"}],\"priority\":1,\"recoveryTime\":\"2026-05-12T13:43:36Z\",\"sNssais\":[{\"sst\":1},{\"sd\":\"000001\",\"sst\":1},{\"sd\":\"00007B\",\"sst\":222}]},\"didDocument\":{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/suites/secp256k1-2019/v1\"],\"assertionMethod\":[\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1\"],\"authentication\":[\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1\"],\"controller\":\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606\",\"created\":\"2026-05-12T13:43:36Z\",\"id\":\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606\",\"updated\":\"2026-05-12T13:43:36Z\",\"verificationMethod\":[{\"controller\":\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606\",\"id\":\"did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1\",\"publicKeyMultibase\":\"zpg3FRVCaspCb4GcKHg9uwf1wjY5GvHH7te2wvo48yFyV\",\"type\":\"EcdsaSecp256k1VerificationKey2019\"}]},\"registeredAt\":\"2026-05-12T13:43:44Z\",\"updatedAt\":\"2026-05-12T13:43:44Z\"}"
  ],
  "receipt": {
    "valid": 1,
    "result": [
      "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
      "OK"
    ]
  }
}

curl -s http://127.0.0.1:8004/block/getRecentTransactions/10 \
>   | jq '.data.transactionList[] | {
>       txID,
>       sender,
>       did: .args[0],
>       valid: .receipt.valid,
>       result: .receipt.result,
>       nfProfile: (.args[1] | fromjson | .nfProfile),
>       didDocument: (.args[1] | fromjson | .didDocument)
>     }'
{
  "txID": "a23f967d90f388f35aab881990682be21c2e30ce05f8f36ef25a06a423e5b450",
  "sender": "9139989c02cfb456823677af544ac7c72d4bcba3",
  "did": "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
  "valid": 1,
  "result": [
    "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
    "OK"
  ],
  "nfProfile": {
    "amfInfo": {
      "amfRegionId": "01",
      "amfSetId": "001",
      "guamiList": [
        {
          "amfId": "0100101",
          "plmnId": {
            "mcc": "208",
            "mnc": "95"
          }
        },
        {
          "amfId": "0100101",
          "plmnId": {
            "mcc": "001",
            "mnc": "01"
          }
        }
      ]
    },
    "capacity": 30,
    "fqdn": "127.0.0.1",
    "heartBeatTimer": 50,
    "nfInstanceId": "2a49571a-bbf0-4b23-bc6b-284657095543",
    "nfServices": [
      {
        "ipEndPoints": [
          {
            "ipv4Address": "127.0.0.1",
            "port": 8080,
            "transport": "TCP"
          }
        ],
        "nfServiceStatus": "REGISTERED",
        "scheme": "http",
        "serviceInstanceId": "2a49571a-bbf0-4b23-bc6b-284657095543",
        "serviceName": "namf-comm",
        "versions": [
          {
            "apiFullVersion": "1.0.0",
            "apiVersionInUri": "v1"
          }
        ]
      },
      {
        "ipEndPoints": [
          {
            "ipv4Address": "127.0.0.1",
            "port": 8080,
            "transport": "TCP"
          }
        ],
        "nfServiceStatus": "REGISTERED",
        "scheme": "http",
        "serviceInstanceId": "namf-evts",
        "serviceName": "namf-evts",
        "versions": [
          {
            "apiFullVersion": "1.0.0",
            "apiVersionInUri": "v1"
          }
        ]
      }
    ],
    "nfStatus": "REGISTERED",
    "nfType": "AMF",
    "perPlmnSnssaiList": [
      {
        "plmnId": {
          "mcc": "208",
          "mnc": "95"
        },
        "sNssaiList": [
          {
            "sst": 1
          },
          {
            "sd": "000001",
            "sst": 1
          },
          {
            "sd": "00007B",
            "sst": 222
          }
        ]
      }
    ],
    "plmnList": [
      {
        "mcc": "208",
        "mnc": "95"
      }
    ],
    "priority": 1,
    "recoveryTime": "2026-05-12T13:43:36Z",
    "sNssais": [
      {
        "sst": 1
      },
      {
        "sd": "000001",
        "sst": 1
      },
      {
        "sd": "00007B",
        "sst": 222
      }
    ]
  },
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/secp256k1-2019/v1"
    ],
    "assertionMethod": [
      "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1"
    ],
    "authentication": [
      "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1"
    ],
    "controller": "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
    "created": "2026-05-12T13:43:36Z",
    "id": "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
    "updated": "2026-05-12T13:43:36Z",
    "verificationMethod": [
      {
        "controller": "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
        "id": "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606#key-1",
        "publicKeyMultibase": "zpg3FRVCaspCb4GcKHg9uwf1wjY5GvHH7te2wvo48yFyV",
        "type": "EcdsaSecp256k1VerificationKey2019"
      }
    ]
  }
}
zhang@zhang:~/BCF$ curl -s http://127.0.0.1:8004/block/getRecentTransactions/10 \
>   | jq '.data.transactionList[] | {
>       txID,
>       did: .args[0],
>       nfType: (.args[1] | fromjson | .nfProfile.nfType),
>       nfStatus: (.args[1] | fromjson | .nfProfile.nfStatus),
>       nfInstanceId: (.args[1] | fromjson | .nfProfile.nfInstanceId),
>       registeredAt: (.args[1] | fromjson | .registeredAt),
>       valid: .receipt.valid
>     }'
{
  "txID": "a23f967d90f388f35aab881990682be21c2e30ce05f8f36ef25a06a423e5b450",
  "did": "did:oai5gc:1c432f845cb1c50a65d9437a597cbf35:04c4557acae507d1d5460ee7e147c99dcff2edeb3592c599d5a43579dfdfbe01d4f1a86a448f63931f5c78253cdaeb3f776b4a4af9b5c85ac98aec768b1333f606",
  "nfType": "AMF",
  "nfStatus": "REGISTERED",
  "nfInstanceId": "2a49571a-bbf0-4b23-bc6b-284657095543",
  "registeredAt": "2026-05-12T13:43:44Z",
  "valid": 1
}