package main

import (
	// "udidGUI/FLAPI"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"net/http"
	"net/url"
	"p3Chain/api"
	"p3Chain/ginHttp/pkg/app"
	e "p3Chain/ginHttp/pkg/error"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func SendVCrequest(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{c}
		// 假设 destinationHost 作为路由参数或从配置中传递
		destinationHost := c.Param("destinationHost")
		destinationPort := c.Param("destinationPort")
		SubjectDID := c.PostForm("SubjectDID")
		Validity := c.PostForm("Validity")
		Purpose := c.PostForm("Purpose")
		Reassign := c.PostForm("Reassign")
		IssuerAddress := c.PostForm("IssuerAddress")
		SubjectAddress := c.PostForm("SubjectAddress")
		// Signature := c.PostForm("Signature")

		Identifier := uuid.New().String()

		// response_return := map[string]interface{}{
		// 	"success": "VC template has been received..",
		// }

		// c.JSON(http.StatusOK, response_return)

		// 构造目标 URL
		// destinationURL := fmt.Sprintf("http://%s:%s/dper/vcreceive", destinationHost, destinationPort)
		destinationURL := fmt.Sprintf("http://%s:%s/vcreceive", destinationHost, destinationPort)

		// 准备要发送的数据
		formData := url.Values{
			"SubjectDID":     {SubjectDID},
			"Issuer":         {Identifier},
			"Validity":       {Validity},
			"Purpose":        {Purpose},
			"Reassign":       {Reassign},      // 是否允许二次转让
			"IssuerAddress":  {IssuerAddress}, // issuer address
			"SubjectAddress": {SubjectAddress},
		}

		// 发送 HTTP POST 请求
		resp, err := http.PostForm(destinationURL, formData)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, err)
			return
		}
		defer resp.Body.Close()

		// 读取响应内容
		// body, err := ioutil.ReadAll(resp.Body)
		// if err != nil {
		// 	appG.Response(http.StatusInternalServerError, e.ERROR, err)
		// 	return
		// }

		// // 解码 JSON 响应
		// var response map[string]interface{}
		// err = json.Unmarshal(body, &response)
		// if err != nil {
		// 	appG.Response(http.StatusInternalServerError, e.ERROR, err)
		// 	return
		// }

		body, _ := ioutil.ReadAll(resp.Body)

		// 解码 JSON 响应
		var response map[string]interface{}
		_ = json.Unmarshal(body, &response)

		// responseString := string(body)
		c.JSON(http.StatusOK, response)

		// response["SentFormData"] = formData
		// c.JSON(http.StatusOK, response)

	}
}

func VCReceive(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{c}

		// 从请求中获取 SubjectDID 和 Identifier
		subjectDID := c.PostForm("SubjectDID")
		Identifier := c.PostForm("Identifier")
		Validity := c.PostForm("Validity")
		Purpose := c.PostForm("Purpose")
		Reassign := c.PostForm("Reassign")
		IssuerAddress := c.PostForm("IssuerAddress")
		SubjectAddress := c.PostForm("SubjectAddress")

		if subjectDID == "" || Identifier == "" || Validity == "" || Purpose == "" || Reassign == "" || IssuerAddress == "" || SubjectAddress == "" {
			appG.Response(http.StatusBadRequest, e.ERROR, "Missing Parameter...")
			return
		}

		// 构造响应
		response := gin.H{
			"SubjectDID":     subjectDID,
			"Identifier":     Identifier,
			"Validity":       Validity,
			"Purpose":        Purpose,
			"Reassign":       Reassign,
			"IssuerAddress":  IssuerAddress,
			"SubjectAddress": SubjectAddress,
		}

		// 返回响应给调用方
		c.JSON(http.StatusOK, response)
	}
}

func VCReceive01(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		var subjectDID string
		// 构造响应
		response := gin.H{
			"success": subjectDID,
		}

		// 返回响应给调用方
		c.JSON(http.StatusOK, response)
	}
}

func main() {

	// router := gin.Default()

	// //初始化api.DperService已经被正确初始化
	// var ds *api.DperService

	// router.POST("/sendvcrequest/:destinationHost/:destinationPort", SendVCrequest(ds))

	// router.Run("127.0.0.1:8080")

	// router.POST("/vcreceive", VCReceive(ds))
	// router.Run(":127.0.0.1:8081")

	router1 := gin.Default()

	// 初始化api.DperService已经被正确初始化
	// 假设ds是有效的，这里仅作示例
	var ds *api.DperService

	// 为第一个服务配置路由和处理函数
	router1.POST("/sendvcrequest/:destinationHost/:destinationPort", SendVCrequest(ds))

	// 使用goroutine在8080端口启动第一个服务
	go func() {
		if err := router1.Run("127.0.0.1:8080"); err != nil {
			// 处理潜在的启动错误
			log.Fatalf("Failed to run server on 127.0.0.1:8080: %v", err)
		}
	}()

	// 为第二个服务创建另一个gin实例
	router2 := gin.Default()

	// 为第二个服务配置路由和处理函数
	router2.POST("/vcreceive", VCReceive(ds))

	// 在8081端口启动第二个服务，不需要使用goroutine，因为这是main函数的最后一条执行语句
	if err := router2.Run("127.0.0.1:8081"); err != nil {
		// 处理潜在的启动错误
		log.Fatalf("Failed to run server on 127.0.0.1:8081: %v", err)
	}

}
