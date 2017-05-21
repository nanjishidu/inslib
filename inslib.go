package inslib

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	//default http setting
	httpDefaultSetting = HttpSetting{
		UserAgent: "InsServer",
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		EnableCookie: true,
		ContentType:  "application/x-www-form-urlencoded",
	}
	//default proxy setting:tcp and http
	proxyDefalutSetting = ProxySetting{}
)

var (
	//home page
	homeUrl = "https://www.instagram.com"
	//single page
	postUrl = "https://www.instagram.com/p/"
	//api request
	queryUrl = "https://www.instagram.com/query/"
	//api query page
	querySearchUrl = "https://www.instagram.com/web/search/topsearch/?query="
)

var (
	loger            = log.New(os.Stdout, "", log.Llongfile)
	defaultCookieJar http.CookieJar
	syncMutex        sync.Mutex
)

//register cookie
func registerCookie() {
	syncMutex.Lock()
	defer syncMutex.Unlock()
	defaultCookieJar, _ = cookiejar.New(nil)
}

//set default setting
func SetHttpSetting(setting HttpSetting) {
	syncMutex.Lock()
	defer syncMutex.Unlock()
	httpDefaultSetting = setting
}
func SetHttpProxy(p string) {
	SetProxySetting(ProxySetting{
		HttpProxy: p,
	})
}

//
func SetTcpProxy(p string) {
	SetProxySetting(ProxySetting{
		TcpProxy: p,
	})
}
func SetProxySetting(setting ProxySetting) {
	syncMutex.Lock()
	defer syncMutex.Unlock()
	proxyDefalutSetting = setting
}
func GetFilenameByUrl(urli string) string {
	s := strings.Split(urli, "/")
	return s[len(s)-1]
}
func Download(node *Node, dir string, IsSplitDay bool, names ...string) (fullname string,
	b bool) {
	var fileType, fileUrli string
	if len(names) == 0 {
		names = []string{"default"}
	}
	if node.IsVideo {
		fileType = "vedio"
		fileUrli = node.VideoUrl
	} else {
		fileType = "image"
		if node.DisplaySrc != "" {
			fileUrli = node.DisplaySrc
		} else if node.DisplayUrl != "" {
			fileUrli = node.DisplayUrl
		}

	}
	if fileUrli == "" {
		return "", b
	}
	fulldir := strings.Join(names, "/") + "/" + fileType
	if IsSplitDay {
		fulldir = "/" + time.Unix(node.Date, 0).Format("2006-01-02")
	}
	fullname = fulldir + "/" + GetFilenameByUrl(fileUrli)
	if !IsExist(dir + "/" + fulldir) {
		Mkdir(dir + "/" + fulldir)
	}
	Get(fileUrli).ToFile(dir + "/" + fullname)
	b = true
	return fullname, b
}
func GetUsers(query string) ([]*Users, error) {
	var i QueryPage
	err := Get(querySearchUrl + query).ToJson(&i)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	if i.Status != "ok" {
		return nil, errors.New("instagram status is not ok")
	}
	return i.Users, err
}
func GetWebPage(urli string) (wp WebPage, err error) {
	webPage, err := Get(urli).String()
	if err != nil {
		return wp, err
	}
	extryData := FindStringSubmatch(webPage, `window._sharedData = (.*);`)
	if extryData == "" {
		return wp, errors.New("webPage extry_data is null")
	}
	err = json.Unmarshal([]byte(extryData), &wp)
	if err != nil {
		return wp, err
	}
	return wp, nil
}

func GetDataByCode(code string) (nodes []*Node, err error) {
	return GetDataByUrl(postUrl + code)
}
func GetDataByUrl(urli string) (nodes []*Node, err error) {
	wp, err := GetWebPage(urli)
	if err != nil {
		return
	}
	if len(wp.ExtryData.PostPage) == 0 {
		return nodes, errors.New("PostPage is null")
	}
	graphql := wp.ExtryData.PostPage[0].Graphql
	if graphql == nil {
		return nodes, errors.New("graphql is null")
	}
	media := graphql.ShortcodeMedia
	if graphql == nil {
		return nodes, errors.New("media is null")
	}
	typeName := media.TypeName
	switch typeName {
	case "GraphSidecar":
		if len(media.EdgeSidecarToChildren.Edges) > 0 {
			for _, v := range media.EdgeSidecarToChildren.Edges {
				v.Node.Date = media.Date
				nodes = append(nodes, v.Node)
			}
		}
	case "GraphVideo":
		fallthrough
	case "GraphImage":
		nodes = append(nodes, media.Node)
	}
	return
}
func GetDataByName(name string) (map[string][]*Node, error) {
	if name == "" {
		return nil, errors.New("name is null")
	}
	var insMap = map[string][]*Node{
		name: []*Node{},
	}
	urli := fmt.Sprintf("%s/%s", homeUrl, name)
	wp, err := GetWebPage(urli)
	if err != nil {
		return insMap, errors.New("user ProfilePage is null")
	}
	if len(wp.ExtryData.ProfilePage) == 0 {
		return insMap, errors.New("user ProfilePage is null")
	}
	var user = wp.ExtryData.ProfilePage[0].User
	if !user.Media.PageInfo.HasNextPage {
		for _, v := range user.Media.Nodes {
			switch v.TypeName {
			case "GraphSidecar":
				fallthrough
			case "GraphVideo":
				nodes, err := GetDataByCode(v.Code)
				if err != nil {
					loger.Println(err)
					continue
				}
				// loger.Println(len(nodes))
				insMap[name] = append(insMap[name], nodes...)
			case "GraphImage":
				insMap[name] = append(insMap[name], v)
			}
		}
		return insMap, nil
	}
	var (
		userId     = user.Id
		mediaStart = user.Media.PageInfo.EndCursor
		csrftoken  = wp.Config.CsrfToken
	)
	for {
		var q = fmt.Sprintf("ig_user(%s) { media.after(%s, %d) {nodes { __typename,code, date, display_src, thumbnail_src},page_info}}",
			userId, mediaStart, 100)
		param := url.Values{}
		param.Add("q", q)
		var i QueryPage
		err := Post(queryUrl, param).SetCsrftoken(csrftoken).SetReferer(urli).ToJson(&i)
		if err != nil {
			return insMap, errors.New(err.Error())
		}
		if i.Status != "ok" {
			return insMap, errors.New("instagram status is not ok")
		}
		// loger.Println(len(i.Media.Nodes))
		for _, v := range i.Media.Nodes {
			switch v.TypeName {
			case "GraphSidecar":
				fallthrough
			case "GraphVideo":
				nodes, err := GetDataByCode(v.Code)
				if err != nil {
					loger.Println(err)
					continue
				}
				// loger.Println(len(nodes))
				insMap[name] = append(insMap[name], nodes...)
			case "GraphImage":
				insMap[name] = append(insMap[name], v)
			}
		}
		if !i.Media.PageInfo.HasNextPage {
			break
		}
		if i.Media.PageInfo.EndCursor == "" {
			break
		}
		mediaStart = i.Media.PageInfo.EndCursor
	}
	return insMap, nil

}

func NewRequest(method, url string, body io.Reader) *HttpRequest {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		log.Println("inslib NewRequest:", err)
	}
	return &HttpRequest{
		req: req,
		setting: setting{
			HttpSetting:  httpDefaultSetting,
			ProxySetting: proxyDefalutSetting,
		},
	}
}

func Get(url string, params ...url.Values) *HttpRequest {
	if len(params) > 0 {
		return NewRequest("GET", url, strings.NewReader((params[0].Encode())))
	}
	return NewRequest("GET", url, nil)
}
func Post(url string, params ...url.Values) *HttpRequest {
	if len(params) > 0 {
		return NewRequest("POST", url, strings.NewReader((params[0].Encode())))
	}
	return NewRequest("POST", url, nil)
}

func (m *HttpRequest) GetRequest() *http.Request {
	return m.req
}

func (m *HttpRequest) UserAget(user_agent string) *HttpRequest {
	m.setting.HttpSetting.UserAgent = user_agent
	return m

}
func (m *HttpRequest) SetReferer(referer string) *HttpRequest {
	m.setting.HttpSetting.Referer = referer
	return m
}
func (m *HttpRequest) SetCsrftoken(csrftoken string) *HttpRequest {
	m.setting.HttpSetting.Csrftoken = csrftoken
	return m
}

func (m *HttpRequest) EnableCookie() *HttpRequest {
	m.setting.HttpSetting.EnableCookie = true
	return m
}
func (m *HttpRequest) SetTcpProxy(p string) *HttpRequest {
	m.setting.ProxySetting.HttpProxy = ""
	m.setting.ProxySetting.TcpProxy = p
	return m
}
func (m *HttpRequest) SetHttpProxy(p string) *HttpRequest {
	m.setting.ProxySetting.HttpProxy = p
	m.setting.ProxySetting.TcpProxy = ""
	return m
}
func (m *HttpRequest) Header(key, value string) *HttpRequest {
	m.req.Header.Set(key, value)
	return m
}
func (m *HttpRequest) DoRequest() (*http.Response, error) {
	var jar http.CookieJar
	if m.setting.HttpSetting.EnableCookie {
		if defaultCookieJar == nil {
			registerCookie()
		}
		jar = defaultCookieJar
	}

	//tcp proxy
	if m.setting.ProxySetting.TcpProxy != "" {
		dialer, err := proxy.SOCKS5("tcp", m.setting.ProxySetting.TcpProxy, nil, proxy.Direct)
		if err != nil {
			loger.Println(err)
		}
		m.setting.HttpSetting.Transport.Dial = dialer.Dial
	} else if m.setting.ProxySetting.HttpProxy != "" {
		//http proxy
		urli := url.URL{}
		httpProxy, err := urli.Parse(m.setting.ProxySetting.HttpProxy)
		if err != nil {
			loger.Println(err)
		}
		m.setting.HttpSetting.Transport.Proxy = http.ProxyURL(httpProxy)
	}
	if m.setting.HttpSetting.UserAgent != "" && m.req.Header.Get("User-Agent") == "" {
		m.req.Header.Set("User-Agent", m.setting.HttpSetting.UserAgent)

	}
	if m.setting.HttpSetting.Referer != "" && m.req.Header.Get("refer") == "" {
		m.req.Header.Set("referer", m.setting.HttpSetting.Referer)
	}
	if m.setting.HttpSetting.Csrftoken != "" && m.req.Header.Get("x-csrftoken") == "" {
		m.req.Header.Set("x-csrftoken", m.setting.HttpSetting.Csrftoken)
	}
	if m.setting.HttpSetting.ContentType != "" && m.req.Header.Get("Content-Type") == "" {
		m.req.Header.Set("Content-Type", m.setting.HttpSetting.ContentType)
	}
	client := &http.Client{
		Transport: m.setting.HttpSetting.Transport,
		Jar:       jar,
	}
	resp, err := client.Do(m.req)
	if err != nil {
		return nil, err
	}
	return resp, nil

}

func (m *HttpRequest) Bytes() ([]byte, error) {
	resp, err := m.DoRequest()
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, errors.New("response body is null")
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, err

}
func (m *HttpRequest) String() (string, error) {
	b, err := m.Bytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
func (m *HttpRequest) ToJson(v interface{}) error {
	b, err := m.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func (m *HttpRequest) ToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := m.DoRequest()
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return errors.New("response body is null")
	}
	defer resp.Body.Close()
	_, err = io.Copy(f, resp.Body)
	return err

}

func FindStringSubmatch(s, m string) string {
	re := regexp.MustCompile(m)
	mc := re.FindStringSubmatch(s)
	if len(mc) == 2 {
		return mc[1]
	}
	return ""
}
func IsExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}
func Mkdir(src string) error {
	if IsExist(src) {
		return nil
	}
	if err := os.MkdirAll(src, 0777); err != nil {
		if os.IsPermission(err) {
		}
		return err
	}

	return nil
}

type HttpRequest struct {
	req     *http.Request
	setting setting
}
type setting struct {
	HttpSetting
	ProxySetting
}
type HttpSetting struct {
	UserAgent    string
	Referer      string
	Csrftoken    string
	ContentType  string
	header       http.Header
	EnableCookie bool
	Transport    *http.Transport
}
type ProxySetting struct {
	HttpProxy string //http proxy
	TcpProxy  string //tcp proxy
}

//ins
//web request struct
type WebPage struct {
	ExtryData    *ExtryData `json:"entry_data"`
	Config       *Config    `json:"config"`
	Hostname     string     `json:"hostname"`
	CountryCode  string     `json:"country_code"`
	LanguageCode string     `json:"language_code"`
	Platform     string     `json:"platform"`
}
type Config struct {
	CsrfToken string `json:"csrf_token"`
}
type ExtryData struct {
	//profile page
	ProfilePage []*ProfilePage `json:"ProfilePage"`
	//post page
	PostPage []*PostPage `json:"PostPage"`
}

type ProfilePage struct {
	User *User `json:"user"`
}
type User struct {
	Id              string `json:"id"`
	Username        string `json:"username"`
	Fullname        string `json:"full_name"`
	ProfilePicUrl   string `json:"profile_pic_url"`
	ProfilePicId    string `json:"profile_pic_id"`
	ProfilePicUrlHd string `json:"profile_pic_url_hd"`
	FollowerCount   int64  `json:"follower_count"`
	FollowBy        *Count `json:"followed_by"`
	Follows         *Count `json:"follows"`
	Media           *Media `json:"media"`
}

type PostPage struct {
	Media   *PostMedia `json:"media"`
	Graphql *Graphql   `json:"graphql"`
}
type Graphql struct {
	ShortcodeMedia *ShortcodeMedia `json:"shortcode_media"`
}
type ShortcodeMedia struct {
	EdgeSidecarToChildren *EdgeSidecarToChildren `json:"edge_sidecar_to_children"`
	*Node
}
type PostMedia struct {
	EdgeSidecarToChildren *EdgeSidecarToChildren `json:"edge_sidecar_to_children"`
	*Node
}
type EdgeSidecarToChildren struct {
	Edges []*Edges `json:"edges"`
}
type Edges struct {
	Node *Node `json:"node"`
}

//api query response struct
type QueryPage struct {
	Status string   `json:"status"`
	Media  *Media   `json:"media"`
	Users  []*Users `json:"users"`
}
type Users struct {
	User *User `json:"user"`
}
type Media struct {
	Nodes    []*Node   `json:"nodes"`
	PageInfo *PageInfo `json:"page_info"`
}

//Node
type Node struct {
	TypeName     string      `json:"__typename"` //GraphSidecar GraphImage GraphVideo
	Id           string      `json:"id"`
	ShortCode    string      `json:"shortcode"`
	Code         string      `json:"code"`
	Date         int64       `json:"date"`
	ThumbnailSrc string      `json:"thumbnail_src"`
	DisplaySrc   string      `json:"display_src"`
	DisplayUrl   string      `json:"display_url"`
	VideoUrl     string      `json:"video_url"`
	IsVideo      bool        `json:"is_video"`
	Comments     *Count      `json:"comments"`
	Likes        *Count      `json:"likes"`
	Dimensions   *Dimensions `json:"dimensions"`
}
type Dimensions struct {
	Height uint32 `json:"height"`
	Width  uint32 `json:"width"`
}
type PageInfo struct {
	HasPreviousPage bool   `json:"has_previous_page"`
	StartCursor     string `json:"start_cursor"`
	EndCursor       string `json:"end_cursor"`
	HasNextPage     bool   `json:"has_next_page"`
}

type Count struct {
	Count int64 `json:"count"`
}
