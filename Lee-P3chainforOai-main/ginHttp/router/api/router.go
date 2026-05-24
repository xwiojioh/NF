package router

import (
	"fmt"
	"net/http"
	"p3Chain/api"
	"p3Chain/ginHttp/pkg/setting"

	"github.com/gin-gonic/gin"
)

func Cors() gin.HandlerFunc {
	return func(context *gin.Context) {
		method := context.Request.Method

		origin := context.Request.Header.Get("Origin")

		if origin != "" {
			context.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			context.Header("Access-Control-Allow-Origin", "*")
		}

		context.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Token, Authorization, X-Session-ID, X-Interaction-ID, X-Subject-DID, X-Peer-DID, X-Subject-NF-Type, X-Peer-NF-Type")
		context.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PATCH, PUT")
		context.Header("Access-Control-Expose-Headers", "Access-Control-Allow-Headers, Token")
		context.Header("Access-Control-Allow-Credentials", "true")

		if method == "OPTIONS" {
			context.AbortWithStatus(http.StatusNoContent)
		}
	}
}

func InitRouter(bs *api.BlockService, ds *api.DperService, ns *api.NetWorkService, ct *api.ContractService, auditSvc *api.AuditService) *gin.Engine {

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(AuditContextMiddleware())

	r.Use(Cors())
	SetAuditService(auditSvc)

	gin.SetMode(setting.ServerSetting.RunMode)

	block := r.Group("block")
	network := r.Group("network")
	dper := r.Group("dper")

	contract := r.Group("contract")

	if bs != nil {
		block.GET("/blockNumber", GetCurrentBlockNumber(bs))
		block.GET("/blockHash", GetCurrentBlockHash(bs))
		block.GET("/getBlockByHash/:hash", GetBlockByHash(bs))
		block.GET("/getBlockByNumber/:number", GetBlockByNumber(bs))
		block.GET("/getBlockHashByNumber/:number", GetBlockHashByNumber(bs))
		block.GET("/getRecentBlocks/:count", GetRecentBlocks(bs))
		block.GET("/getAllBlocks", GetAllBlocks(bs))

		block.GET("/getTransactionNumber", GetTransactionNumber(bs))
		block.GET("/getTransactionByHash/:hash", GetTransactionByHash(bs))
		block.GET("/getTransactionByBlockHashAndIndex", GetTransactionByBlockHashAndIndex(bs))
		block.GET("/getTransactionsByBlockHash/:blockHash", GetTransactionsByBlockHash(bs))
		block.GET("/getTransactionsByBlockNumber/:blockNumber", GetTransactionsByBlockNumber(bs))
		block.GET("/getRecentTransactions/:count", GetRecentTransactions(bs))
		block.GET("/getAllTransactions", GetAllTransactions(bs))

		block.GET("/getAvgValidTxRateInRecentBlocks/:count", GetAvgValidTxRateInRecentBlocks(bs))
		block.GET("/getAvgBlockInterval/:count", GetAvgBlockInterval(bs))
		block.GET("/getRecentBlocksTPS/:count", GetRecentBlocksTPS(bs))

	}

	if ds != nil {
		dper.GET("/accountsList", BackAccountList(ds))
		dper.POST("/newAccount", CreateNewAccount(ds))
		dper.POST("/useAccount", UseAccount(ds))
		dper.GET("/currentAccount", CurrentAccount(ds))
		dper.POST("/txCheck", OpenTxCheckMode(ds))
		dper.POST("/solidInvoke", SolidInvoke(ds))
		dper.POST("/solidCall", SolidCall(ds))
		dper.POST("/softCall", SoftCall(ds))
		dper.POST("/softInvoke", SoftInvoke(ds))

		dper.POST("/signaturereturn", SignatureReturn(ds))
		dper.POST("/signaturereturn2", SignatureReturn2(ds))
		dper.POST("/signvalid", SignValid(ds))
		dper.POST("/vcreceive", VCReceive(ds))
		dper.GET("/getvcresponse", GetVCResponse(ds)) //添加的新的router
		dper.POST("/vcreceive2", VCReceive2(ds))
		dper.POST("/vcvalid", VCValid(ds))
		dper.POST("/datasend", DataSend(ds))
		dper.POST("/datasend2", DataSend(ds))
		dper.POST("/getaddress", GetAddress(ds))
		dper.POST("/transvc", TransVC(ds))
		dper.POST("/setdid", SetDID(ds))
		// dper.POST("/setdid_baseline", SetDID_baseline_experiment(ds))
		dper.POST("/sendvcrequest/:destinationHost/:destinationPort", SendVCrequest(ds))
		dper.POST("/sendvc/:destinationHost/:destinationPort", SendVC(ds))
		dper.POST("/sendrandom/:destinationHost/:destinationPort", SendRandom(ds))
		dper.POST("/transvcrequest/:destinationHost/:destinationPort", TransVCrequest(ds))
		dper.POST("/datarequest/:destinationHost/:destinationPort", DataRequest(ds))
		dper.POST("/datarequest2/:destinationHost/:destinationPort", DataRequest2(ds))
		dper.POST("/publishTx", PublishTx(ds))

		dper.POST("/AMFsend/:destinationHost/:destinationPort", AMFsend(ds))
		dper.POST("/SMFreceive", SMFreceive(ds))

		dper.POST("/setdidnew", SetDIDNEW(ds))
		dper.GET("/listdids", ListDIDs(ds))
		dper.POST("/getdid", GetDID(ds))
		dper.POST("/updatedid", UpdateDID(ds))
		dper.POST("/revokedid", RevokeDID(ds))
		dper.POST("/verifydid", VerifyDID(ds))
		dper.GET("/metrics", GetMetrics(ds))
		fmt.Println("=== DEBUG: Registering BCF routes ===")
		bcf := r.Group("bcf")
		bcf.GET("/nf_instances", GetNFInstance(ds))
		bcf.GET("/pubkey/:did", GetPublicKey(ds))
		fmt.Println("=== DEBUG: BCF routes registered ===")

		// BCF 自定义路径（与 AMF 侧现有联调代码保持一致，使用下划线风格）
		fmt.Println("=== DEBUG: Registering NBCF routes ===")
		nbcf_management := r.Group("/nbcf_management/v1")
		nbcf_management.PUT("/nf_instances/:nfInstanceId", RegisterNF(ds))
		nbcf_management.DELETE("/nf_instances/:nfInstanceId", DeregisterNF(ds))
		nbcf_management.GET("/nf_instances", GetNFInstance(ds))
		nbcf_management.GET("/audit-logs",
			TokenAuthMiddleware(PermAuditRead),
			GetAuditLogs(auditSvc))
		nbcf_management.GET("/audit-logs/:auditId",
			TokenAuthMiddleware(PermAuditRead),
			GetAuditLogByID(auditSvc))

		nbcf_audit := r.Group("/nbcf_audit/v1")
		nbcf_audit.POST("/session-digests",
			TokenAuthMiddleware(PermAuditAnchor),
			PostSessionDigest(auditSvc))
		nbcf_audit.GET("/session-digests",
			TokenAuthMiddleware(PermAuditRead),
			GetSessionDigest(auditSvc))
		nbcf_audit.GET("/session-digests/:sessionId",
			TokenAuthMiddleware(PermAuditRead),
			GetSessionDigest(auditSvc))
		nbcf_audit.POST("/verify",
			TokenAuthMiddleware(PermAuditRead),
			VerifySessionDigest(auditSvc))
		nbcf_audit.POST("/verify-events",
			TokenAuthMiddleware(PermAuditRead),
			VerifySessionEvents(auditSvc))

		registerSubscriptionRoutes := func(group *gin.RouterGroup) {
			group.POST("/subscriptions",
				TokenAuthMiddleware(PermSubscriptionCreate),
				CreateSubscription(ds))
			group.GET("/subscriptions",
				TokenAuthMiddleware(PermSubscriptionManage),
				GetSubscriptions(ds))
			group.GET("/subscriptions/:subscriptionId",
				TokenAuthMiddleware(PermSubscriptionManage),
				GetSubscriptionByID(ds))
			group.DELETE("/subscriptions/:subscriptionId",
				TokenAuthMiddleware(PermSubscriptionDelete),
				DeleteSubscription(ds))
		}

		// AMF 当前使用 /nbcf_management/v1/subscriptions 路径，BCF 在此直接兼容该路径。
		registerSubscriptionRoutes(nbcf_management)
		fmt.Println("=== DEBUG: NBCF routes registered ===")

		nbcf_discovery := r.Group("/nbcf_discovery/v1")
		nbcf_discovery.GET("/nf_instances",
			TokenAuthMiddleware(PermServiceDiscovery),
			DiscoverNF(ds))

		nbcf_auth := r.Group("/nbcf_auth/v1")
		nbcf_auth.POST("/challenges", CreateChallenge(ds))
		nbcf_auth.POST("/verify", VerifyChallenge(ds))
		nbcf_auth.GET("/states/:did", GetAuthState(ds))
		// AMF/AUSF/SMF 等 NF 向 BCF 自身认证的接口（challenge-response，secp256k1 DER 签名）
		nbcf_auth.POST("/auth/init", BcfAuthInit(ds))
		nbcf_auth.POST("/auth/verify", BcfAuthVerify(ds))

		// 保留旧的订阅路径，避免已有测试脚本或客户端失效。
		nbcf_subscription := r.Group("/nbcf_subscription/v1")
		registerSubscriptionRoutes(nbcf_subscription)
	}

	if ns != nil {
		network.GET("/networkInfo", BackDPNetWork(ns))
		network.GET("/allConsensusNode", BackAllConsensusNode(ns))
		network.GET("/selfNodeInfo", BackNodeInfoSelf(ns))
		network.POST("/nodeInfoByNodeID", BackNodeInfoByNodeID(ns))

		network.GET("/groupCount", BackGroupCount(ns))
		network.GET("/allGroupName", BackAllGroupName(ns))
		network.GET("/upperNet", BackUpperNetNodeList(ns))
		network.GET("/allBooters", BackAllBooters(ns))
		network.GET("/allLeaders", BackAllLeaders(ns))
		network.POST("/subNetNodeID", BackNodeListByGroupName(ns))
		network.POST("/subNetLeaderID", BackLeaderNodeIDByGroupName(ns))
		network.POST("/subNetInfo", BackSubNetByGroupName(ns))

	}

	if ct != nil {
		contract.GET("/credit", BackCredit(ct))
		contract.GET("/stampList", BackStampList(ct))
		contract.POST("/mintNewStamp", MintNewStamp(ct))
		contract.POST("/transStamp", TransStamp(ct))
	}

	return r

}
