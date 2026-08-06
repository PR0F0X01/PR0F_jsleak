package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"math"
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
	Context string
}

var (
	resultsMu sync.Mutex
	results   []secretResult
)

func regexGrep(content string, baseURL string, patterns []patternDef) {
	const contextRadius = 40

	for _, p := range patterns {
		r, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}

		locs := r.FindAllStringIndex(content, -1)

		for _, loc := range locs {
			start, end := loc[0], loc[1]
			v := content[start:end]

			ctxStart := start - contextRadius
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := end + contextRadius
			if ctxEnd > len(content) {
				ctxEnd = len(content)
			}
			ctx := strings.ReplaceAll(content[ctxStart:ctxEnd], "\n", " ")

			resultsMu.Lock()
			results = append(results, secretResult{
				URL:     baseURL,
				Pattern: p.Name,
				Value:   v,
				Context: ctx,
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

// ---- Structured JSON output types (preprocessing stage for skill dispatch) ----

type candidateJSON struct {
	SecretID          string  `json:"secret_id"`
	CandidateValue    string  `json:"candidate_value"`
	Classification    string  `json:"classification"`
	Reason            string  `json:"reason"`
	ServiceType       string  `json:"service_type"`
	AssociatedContext string  `json:"associated_context"`
	SelectedSkill     string  `json:"selected_skill"`
	ValidationResult  string  `json:"validation_result"`
	FailureReason     string  `json:"failure_reason"`
	Evidence          string  `json:"evidence"`
	ReportingStatus   string  `json:"reporting_status"`
	EntropyScore      float64 `json:"entropy_score"`
	EntropyStatus     string  `json:"entropy_status"`
}

type urlEntryJSON struct {
	URLID      string          `json:"url_id"`
	SourceURL  string          `json:"source_url"`
	Status     string          `json:"status"`
	Candidates []candidateJSON `json:"candidates"`
}

type metaJSON struct {
	Version     int    `json:"version"`
	GeneratedBy string `json:"generated_by"`
	LastUpdated string `json:"last_updated"`
}

type chunkJSON struct {
	Meta metaJSON       `json:"_meta"`
	URLs []urlEntryJSON `json:"urls"`
}

// shannonEntropy يحسب الـ Shannon entropy لسلسلة نصية.
// ده مقياس بسيط شائع الاستخدام في أدوات كشف الـ secrets
// (زي trufflehog وgitleaks) للتمييز بين قيم عشوائية عالية
// الاحتمالية إنها مفاتيح/توكنز حقيقية، وقيم متكررة/نمطية
// احتمال كبير تكون false positive.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// entropyStatus يحدد الحالة (HIGH/LOW) بناءً على threshold قابل للتهيئة.
// لا يتم حذف أي candidate بسبب الـ entropy المنخفض، بس بيتعلّم عليه
// عشان الـ sub-agents تقرر لاحقًا تعالجه ولا تتخطاه.
func entropyStatus(score, threshold float64) string {
	if score >= threshold {
		return "HIGH"
	}
	return "LOW"
}

// buildStructuredOutput يحوّل النتائج المرتبة (بعد sort + dedupe) إلى
// url entries مجمّعة، مع ترقيم url_id تسلسلي، وترقيم secret_id محلي
// داخل كل URL (يبدأ من جديد مع كل URL جديد).
func buildStructuredOutput(res []secretResult, entropyThreshold float64) []urlEntryJSON {
	var entries []urlEntryJSON

	urlIndex := 0
	var current *urlEntryJSON

	for _, r := range res {
		if current == nil || current.SourceURL != r.URL {
			if current != nil {
				entries = append(entries, *current)
			}
			urlIndex++
			current = &urlEntryJSON{
				URLID:     fmt.Sprintf("U-%03d", urlIndex),
				SourceURL: r.URL,
				Status:    "PENDING",
			}
		}

		score := shannonEntropy(r.Value)
		secretNum := len(current.Candidates) + 1

		current.Candidates = append(current.Candidates, candidateJSON{
			SecretID:          fmt.Sprintf("S-%03d", secretNum),
			CandidateValue:    r.Value,
			Classification:    r.Pattern,
			Reason:            fmt.Sprintf("Matched regex pattern: %s", r.Pattern),
			ServiceType:       "",
			AssociatedContext: r.Context,
			SelectedSkill:     "",
			ValidationResult:  "PENDING",
			FailureReason:     "",
			Evidence:          r.Context,
			ReportingStatus:   "PENDING",
			EntropyScore:      score,
			EntropyStatus:     entropyStatus(score, entropyThreshold),
		})
	}
	if current != nil {
		entries = append(entries, *current)
	}

	return entries
}

// splitByEntropy بتقسم كل url entry لجزئين: candidates بحالة HIGH
// وcandidates بحالة LOW، وبتبني url entries منفصلة لكل نوع.
// الـ secret_id بيفضل زي ما اتولّد أصلًا (مش بيتعاد ترقيمه)، عشان
// التتبّع بين الملفين يفضل صحيح.
func splitByEntropy(entries []urlEntryJSON) (highEntries, lowEntries []urlEntryJSON) {
	for _, e := range entries {
		var highCandidates, lowCandidates []candidateJSON
		for _, c := range e.Candidates {
			if c.EntropyStatus == "HIGH" {
				highCandidates = append(highCandidates, c)
			} else {
				lowCandidates = append(lowCandidates, c)
			}
		}

		if len(highCandidates) > 0 {
			highEntries = append(highEntries, urlEntryJSON{
				URLID:      e.URLID,
				SourceURL:  e.SourceURL,
				Status:     e.Status,
				Candidates: highCandidates,
			})
		}
		if len(lowCandidates) > 0 {
			lowEntries = append(lowEntries, urlEntryJSON{
				URLID:      e.URLID,
				SourceURL:  e.SourceURL,
				Status:     e.Status,
				Candidates: lowCandidates,
			})
		}
	}
	return highEntries, lowEntries
}

// writeLowEntropyFile بيكتب كل الـ LOW entropy candidates في ملف
// JSON واحد لوحده (من غير تقسيم لـ chunks)، بنفس هيكل _meta/urls.
func writeLowEntropyFile(entries []urlEntryJSON, outputDir, generatedBy string) error {
	if len(entries) == 0 {
		return nil
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	chunk := chunkJSON{
		Meta: metaJSON{
			Version:     1,
			GeneratedBy: generatedBy,
			LastUpdated: time.Now().UTC().Format(time.RFC3339),
		},
		URLs: entries,
	}

	fileName := filepath.Join(outputDir, "low_entropy_candidates.json")
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(chunk)
}

// writeJSONChunks يقسم url entries إلى ملفات chunk_NNN.json،
// بحد أقصى maxURLsPerChunk عنصر URL لكل ملف (وليس عدد أسطر/candidates).
func writeJSONChunks(entries []urlEntryJSON, maxURLsPerChunk int, outputDir, generatedBy string) error {
	if len(entries) == 0 {
		return nil
	}

	if maxURLsPerChunk <= 0 {
		maxURLsPerChunk = 100
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	chunkNum := 1
	for i := 0; i < len(entries); i += maxURLsPerChunk {
		end := i + maxURLsPerChunk
		if end > len(entries) {
			end = len(entries)
		}
		chunkEntries := entries[i:end]

		chunk := chunkJSON{
			Meta: metaJSON{
				Version:     1,
				GeneratedBy: generatedBy,
				LastUpdated: time.Now().UTC().Format(time.RFC3339),
			},
			URLs: chunkEntries,
		}

		fileName := filepath.Join(outputDir, fmt.Sprintf("chunk_%03d.json", chunkNum))
		f, err := os.Create(fileName)
		if err != nil {
			return err
		}

		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(chunk); err != nil {
			f.Close()
			return err
		}
		f.Close()

		chunkNum++
	}

	return nil
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
		if res[i].URL == last.URL && res[i].Pattern == last.Pattern && res[i].Value == last.Value {
			continue
		}
		deduped = append(deduped, res[i])
	}
	return deduped
}

func main() {
	var concurrency int
	var enableLinkFinder, completeURL, checkStatus, enableSecretFinder bool
	var yamlFilePath string
	var outputDir string
	var maxURLsPerChunk int
	var entropyThreshold float64

	flag.BoolVar(&enableLinkFinder, "l", false, "Enable linkFinder")
	flag.BoolVar(&completeURL, "e", false, "Complete scope URL or not")
	flag.BoolVar(&checkStatus, "k", false, "Check status codes for found links")
	flag.BoolVar(&enableSecretFinder, "s", false, "Enable secretFinder")
	flag.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	flag.StringVar(&yamlFilePath, "t", "", "Path to YAML file containing regex patterns")
	flag.StringVar(&outputDir, "o", "output", "Output directory for JSON chunks")
	flag.IntVar(&maxURLsPerChunk, "max-urls-per-chunk", 100, "Max number of URLs per JSON chunk file (chunk_NNN.json)")
	flag.Float64Var(&entropyThreshold, "entropy-threshold", 3.5, "Entropy threshold used to mark candidates as HIGH/LOW (candidates are never discarded)")
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

		// الإخراج: بنفصل الـ candidates حسب حالة الـ entropy.
		// HIGH → chunk_NNN.json (مقسّمة بـ --max-urls-per-chunk).
		// LOW  → ملف واحد منفصل low_entropy_candidates.json.
		structured := buildStructuredOutput(results, entropyThreshold)
		highEntries, lowEntries := splitByEntropy(structured)

		if err := writeJSONChunks(highEntries, maxURLsPerChunk, outputDir, "PR0F_jsleak"); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON chunks: %v\n", err)
			os.Exit(1)
		}
		if err := writeLowEntropyFile(lowEntries, outputDir, "PR0F_jsleak"); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing low entropy file: %v\n", err)
			os.Exit(1)
		}
	}
}
