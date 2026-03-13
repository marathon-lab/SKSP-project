package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/service-marathon-app/server/pkg/jwt"
)

const UserIDKey = "user_id"

func Auth(jwtManager *jwt.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
			return
		}

		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
			return
		}

		claims, err := jwtManager.Parse(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set(UserIDKey, claims.UserID)
		c.Next()
	}
}

func GetUserID(c *gin.Context) int64 {
	id, _ := c.Get(UserIDKey)
	return id.(int64)
}
