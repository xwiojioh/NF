package ginHttp

import (
	"fmt"
	"net/http"
	"p3Chain/api"
	"p3Chain/ginHttp/pkg/setting"
	router "p3Chain/ginHttp/router/api"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func NewGinRouter(bs *api.BlockService, ds *api.DperService, ns *api.NetWorkService, ct *api.ContractService) {

	setting.Setup()

	var auditService *api.AuditService
	if ds != nil {
		auditService = api.NewAuditService(ds, 1024, 4, 3)
		auditService.Start()
	}

	ginRouter := router.InitRouter(bs, ds, ns, ct, auditService) //返回一个gin路由器

	// 创建 HTTP/2 h2c 服务器
	h2s := &http2.Server{}

	s := &http.Server{
		Addr:           setting.ServerSetting.IP + fmt.Sprintf(":%d", setting.ServerSetting.HttpPort),
		Handler:        h2c.NewHandler(ginRouter, h2s), // 使用 h2c 包装
		ReadTimeout:    setting.ServerSetting.ReadTimeout,
		WriteTimeout:   setting.ServerSetting.WriteTimeout,
		MaxHeaderBytes: 1 << 20,
	}

	fmt.Printf("BCF Server starting on %s (HTTP/2 h2c enabled)\n", s.Addr)
	s.ListenAndServe()
}
