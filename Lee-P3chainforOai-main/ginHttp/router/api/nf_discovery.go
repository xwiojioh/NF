package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"p3Chain/api"
	"p3Chain/ginHttp/pkg/app"
	e "p3Chain/ginHttp/pkg/error"
	loglogrus "p3Chain/log_logrus"

	"github.com/gin-gonic/gin"
)

// DiscoverNF - 按 nfType 发现所有可用 NF 实例
// GET /nbcf_discovery/v1/nf-instances?target-nf-type=AUSF
func DiscoverNF(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		loglogrus.Log.Infof("Http: Get user request -- DiscoverNF\n")
		appG := app.Gin{C: c}

		// 1. 从请求参数取 target-nf-type
		targetNFType := c.Query("target-nf-type")
		if targetNFType == "" {
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "Missing required parameter: target-nf-type",
			})
			return
		}

		loglogrus.Log.Infof("DiscoverNF: target-nf-type = %s\n", targetNFType)

		// 2. 调用链上合约的 DiscoverNFByType
		contractName := "DID::SPECTRUM::TRADE"
		callCmd := "call " + contractName + " DiscoverNFByType -args " + targetNFType

		data, err := ds.SoftCall(callCmd)
		if err != nil || len(data) == 0 || data[0] == "" {
			loglogrus.Log.Infof("DiscoverNF: No NF instances found for type %s\n", targetNFType)
			SubmitAudit(c, GetAuditService(), &api.AuditEvent{
				OperatorDID:    GetCallerDID(c),
				OperationType:  "DISCOVERY",
				TargetObjectID: targetNFType,
				Result:         "SUCCESS",
				ResultCode:     http.StatusOK,
				Metadata: map[string]string{
					"target_nf_type": targetNFType,
					"result_count":   "0",
				},
			})
			c.JSON(http.StatusOK, gin.H{
				"nfInstances": []interface{}{},
			})
			return
		}

		// 3. 解析合约返回的 JSON 数组
		var nfInstances []map[string]interface{}
		if err := json.Unmarshal([]byte(data[0]), &nfInstances); err != nil {
			loglogrus.Log.Errorf("DiscoverNF: Failed to parse result: %v\n", err)
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "Failed to parse discovery result",
			})
			return
		}

		// 4. 返回结果
		loglogrus.Log.Infof("DiscoverNF: Found %d instances for type %s\n", len(nfInstances), targetNFType)
		SubmitAudit(c, GetAuditService(), &api.AuditEvent{
			OperatorDID:    GetCallerDID(c),
			OperationType:  "DISCOVERY",
			TargetObjectID: targetNFType,
			Result:         "SUCCESS",
			ResultCode:     http.StatusOK,
			Metadata: map[string]string{
				"target_nf_type": targetNFType,
				"result_count":   fmt.Sprintf("%d", len(nfInstances)),
			},
		})
		c.JSON(http.StatusOK, gin.H{
			"nfInstances": nfInstances,
		})
	}
}
