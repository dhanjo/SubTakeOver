package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type Service struct {
	Name  string
	Regex string
}

var services = []Service{
	{Name: "AWS/S3", Regex: `The specified bucket does not exist`},
	{Name: "GitHub", Regex: `There isn\\'t a GitHub Pages site here`},
	{Name: "Heroku", Regex: `no such app`},
	{Name: "Fastly", Regex: `Fastly error: unknown domain`},
	{Name: "Shopify", Regex: `Sorry, this shop is currently unavailable.`},
	{Name: "BitBucket", Regex: `Repository not found`},
	// Add more services as needed...
}

type RequestPayload struct {
	Subdomains []string `json:"subdomains"`
}

type SubdomainResult struct {
	Subdomain    string `json:"subdomain"`
	Vulnerable   bool   `json:"vulnerable"`
	Service      string `json:"service,omitempty"`
	CNAME        string `json:"cname,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type ResponsePayload struct {
	Results []SubdomainResult `json:"results"`
}

func checkSubdomain(url string, client *http.Client) SubdomainResult {
	result := SubdomainResult{
		Subdomain: url,
	}

	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	// Perform DNS lookup to fetch CNAME
	cname, err := net.LookupCNAME(strings.TrimPrefix(url, "http://"))
	if err == nil {
		result.CNAME = cname
	} else {
		result.ErrorMessage = fmt.Sprintf("DNS lookup failed: %v", err)
	}

	// Perform HTTP request
	resp, err := client.Get(url)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.HTTPStatus = resp.StatusCode
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to read response body: %v", err)
		return result
	}

	content := string(body)
	for _, service := range services {
		matched, _ := regexp.MatchString(service.Regex, content)
		if matched {
			result.Vulnerable = true
			result.Service = service.Name
			return result
		}
	}

	result.Vulnerable = false
	return result
}

func processSubdomains(subdomains []string) []SubdomainResult {
	var wg sync.WaitGroup
	results := make([]SubdomainResult, 0, len(subdomains))
	resultsChan := make(chan SubdomainResult, len(subdomains))
	client := &http.Client{}

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			resultsChan <- checkSubdomain(url, client)
		}(subdomain)
	}

	wg.Wait()
	close(resultsChan)

	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

func subdomainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var payload RequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	results := processSubdomains(payload.Subdomains)
	response := ResponsePayload{Results: results}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func main() {
	http.HandleFunc("/api/check", subdomainHandler)
	fmt.Println("Server is running on port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
	}
}
