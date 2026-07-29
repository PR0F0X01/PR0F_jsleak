package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type patternDef struct {
	Name       string `yaml:"name"`
	Regex      string `yaml:"regex"`
	Confidence string `yaml:"confidence"`
}

type patternWrapper struct {
	Pattern patternDef `yaml:"pattern"`
}

type yamlPatterns struct {
	Patterns []patternWrapper `yaml:"patterns"`
}

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	},
}

func request(fullurl string, printStatus bool) string {
	req, err := http.NewRequest("GET", fullurl, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ""
	}

	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ""
	}
	defer resp.Body.Close()

	if printStatus && resp.StatusCode != 404 {
		fmt.Printf("[Linkfinder] %s : %d\n", fullurl, resp.StatusCode)
	}

	var bodyString string
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return ""
		}
		bodyString = string(bodyBytes)
	}
	return bodyString
}

type secretResult struct {
	URL     string
	Pattern string
	Value   string
}

var (
	resultsMu sync.Mutex
	results   []secretResult
)

func regexGrep(content string, baseURL string, patterns []patternDef) {
	for _, p := range patterns {
		r, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}

		matches := r.FindAllString(content, -1)

		for _, v := range matches {
			resultsMu.Lock()
			results = append(results, secretResult{
				URL:     baseURL,
				Pattern: p.Name,
				Value:   v,
			})
			resultsMu.Unlock()
		}
	}
}

func linkFinder(content, baseURL string, completeURL, printStatus bool) {
	linkRegex := `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
	r := regexp.MustCompile(linkRegex)
	matches := r.FindAllString(content, -1)

	base, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	for _, match := range matches {
		cleanedMatch := strings.Trim(match, `"'`)
		link, err := url.Parse(cleanedMatch)
		if err != nil {
			continue
		}
		if completeURL {
			link = base.ResolveReference(link)
		}
		if printStatus {
			request(link.String(), true)
		} else {
			fmt.Printf("[+] Found link: [%s] in [%s] \n", link.String(), base.String())
		}
	}
}

func loadPatternsFromYAML(filePath string) (*yamlPatterns, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	var yp yamlPatterns
	if err := decoder.Decode(&yp); err != nil {
		return nil, err
	}
	return &yp, nil
}

// sortResults يرتب النتائج حسب URL ثم Pattern ثم Value
// بحيث تكون كل النتائج الخاصة بنفس الـ URL متجاورة.
func sortResults(res []secretResult) {
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].URL != res[j].URL {
			return res[i].URL < res[j].URL
		}
		if res[i].Pattern != res[j].Pattern {
			return res[i].Pattern < res[j].Pattern
		}
		return res[i].Value < res[j].Value
	})
}

// dedupeResults يحذف النتائج المكررة (نفس URL + Pattern + Value).
// يجب استدعاؤها بعد sortResults مباشرة، لأن الترتيب يخلي
// أي عناصر مكررة متجاورة، فالحذف بيبقى بعملية مرور واحدة (O(n)).
func dedupeResults(res []secretResult) []secretResult {
	if len(res) == 0 {
		return res
	}

	deduped := res[:1]
	for i := 1; i < len(res); i++ {
		last := deduped[len(deduped)-1]
		if res[i] == last {
			continue
		}
		deduped = append(deduped, res[i])
	}
	return deduped
}

// writeParts يقسم النتائج (بعد ترتيبها) إلى ملفات part-N.txt
// داخل outputDir/parts، بحد أقصى partSize سطر لكل ملف.
func writeParts(res []secretResult, partSize int, outputDir string) error {
	if len(res) == 0 {
		return nil
	}

	if partSize <= 0 {
		partSize = 500
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	partNum := 1
	for i := 0; i < len(res); i += partSize {
		end := i + partSize
		if end > len(res) {
			end = len(res)
		}
		chunk := res[i:end]

		fileName := filepath.Join(outputDir, fmt.Sprintf("part-%d.txt", partNum))
		f, err := os.Create(fileName)
		if err != nil {
			return err
		}

		w := bufio.NewWriter(f)
		for _, r := range chunk {
			fmt.Fprintf(w, "[%s] [%s] [%s]\n", r.URL, r.Pattern, r.Value)
		}
		if err := w.Flush(); err != nil {
			f.Close()
			return err
		}
		f.Close()

		partNum++
	}

	return nil
}

func main() {
	var concurrency int
	var enableLinkFinder, completeURL, checkStatus, enableSecretFinder bool
	var yamlFilePath string
	var partSize int
	var outputDir string

	flag.BoolVar(&enableLinkFinder, "l", false, "Enable linkFinder")
	flag.BoolVar(&completeURL, "e", false, "Complete scope URL or not")
	flag.BoolVar(&checkStatus, "k", false, "Check status codes for found links")
	flag.BoolVar(&enableSecretFinder, "s", false, "Enable secretFinder")
	flag.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	flag.StringVar(&yamlFilePath, "t", "", "Path to YAML file containing regex patterns")
	flag.IntVar(&partSize, "p", 500, "Max number of lines per output part file")
	flag.StringVar(&outputDir, "o", "output", "Output directory for parts")
	flag.Parse()

	var patterns []patternDef
	if yamlFilePath != "" {
		loadedPatterns, err := loadPatternsFromYAML(yamlFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading YAML patterns: %v\n", err)
			os.Exit(1)
		}
		for _, pw := range loadedPatterns.Patterns {
			patterns = append(patterns, pw.Pattern)
		}
	}

	urls := make(chan string, concurrency)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			urls <- sc.Text()
		}
		close(urls)
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}()

	wg := sync.WaitGroup{}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for vUrl := range urls {
				res := request(vUrl, false)

				if enableSecretFinder && len(patterns) > 0 {
					regexGrep(res, vUrl, patterns)
				}

				if enableLinkFinder {
					linkFinder(res, vUrl, false, false)
				}
				if completeURL {
					linkFinder(res, vUrl, true, false)
				}
				if checkStatus {
					linkFinder(res, vUrl, true, true)
				}
			}
		}()
	}
	wg.Wait()

	// الترتيب والتقسيم يتمّان فقط بعد انتهاء جميع الـ workers،
	// وليس أثناء عملية الـ scanning.
	if enableSecretFinder && len(results) > 0 {
		sortResults(results)
		results = dedupeResults(results)

		if err := writeParts(results, partSize, outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing parts: %v\n", err)
			os.Exit(1)
		}
	}
}
