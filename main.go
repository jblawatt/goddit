package main

/*
 * https://github.com/reddit-archive/reddit/wiki/JSON
 */

import (
	"context"
	hash "crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	yaml "github.com/goccy/go-yaml"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/michaeljs1990/sqlitestore"
	_ "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const redditAccessTokenURL = "https://www.reddit.com/api/v1/access_token"
const redditSubredditsMineURL = "https://oauth.reddit.com/subreddits/mine"
const redditMeURL = "https://oauth.reddit.com/api/v1/me"
const redditOAuthAuthorizeURL = "https://www.reddit.com/api/v1/authorize"
const redditOAuthRevokeTokenURL = "https://www.reddit.com/api/v1/revoke_token"

const redditOAuthBaseURL = "https://oauth.reddit.com"
const redditAnonymousBaseURL = "https://www.reddit.com"

const userAgentDefault = "linux:goddit2:0.0.1 by /u/jblawatt"

const redditUserSessionKey = "redditUser"
const redditSubsSessionKey = "redditSubs"
const redditTokenSessionKey = "redditToken"
const redditStateSessionKey = "redditState"

type key int

const (
	sessionContextKey             key = iota
	redditTokenContextKey         key = iota
	redditUserContextKey          key = iota
	redditSubscriptionsContextKey key = iota
)

var logger log.Logger

// REDDIT TOKEN ------------------------------------

type RedditToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	Created      time.Time
}

func (t *RedditToken) Expired() bool {
	return t.ExpiresAt().Before(time.Now())
}

func (t *RedditToken) ExpiresAt() time.Time {
	duration := time.Second * time.Duration(t.ExpiresIn)
	expAt := t.Created.Add(duration)
	return expAt
}

func (t *RedditToken) InUse() bool {
	return !(t.AccessToken == "")
}

func (t *RedditToken) BaseURL() string {
	if t.InUse() {
		return redditOAuthBaseURL
	} else {
		return redditAnonymousBaseURL
	}
}

// END REDDIT TOKEN ---------------------------------

type RedditConfig struct {
	ClientID      string `yaml:"client_id"`
	ClientSecret  string `yaml:"client_secret"`
	OAuthCallback string `yaml:"oauth_callback"`
	SecretKey     string `yaml:"secret_key"`
	Bind          string `yaml:"bind"`
	SessionsDB    string `yaml:"sessions_db"`
}

func (rc *RedditConfig) HasSecretKey() bool {
	return rc.SecretKey != ""
}

func (rc *RedditConfig) RedditLoginPossible() bool {
	return rc.ClientID != "" && rc.ClientSecret != "" && rc.OAuthCallback != ""
}

func DoRefreshToken(redditToken *RedditToken) {
	log.Println("updating token")
	client := &http.Client{}
	data := url.Values{}
	data.Add("grant_type", "refresh_token")
	data.Add("refresh_token", redditToken.AccessToken)

	request, _ := http.NewRequest("POST", redditAccessTokenURL, strings.NewReader(data.Encode()))
	request.Header.Add("User-Agent", userAgentDefault)
	request.SetBasicAuth(redditConfig.ClientID, redditConfig.ClientSecret)
	resp, _ := client.Do(request)
	json.NewDecoder(resp.Body).Decode(&redditToken)
	redditToken.Created = time.Now()
	log.Println("token update complete")
}

type RedditSubredditImageResolution struct {
	Height int    `json:"height"`
	URL    string `json:"url"`
	Width  string `json:"width"`
}

type RedditSubredditImage struct {
	ID          string                           `json:"id"`
	Resolutions []RedditSubredditImageResolution `json:"resolutions"`
}

type RedditSubredditPreview struct {
	Enabled bool                   `json:"enabled"`
	Images  []RedditSubredditImage `json:"images"`
}

type RedditSubredditListing struct {
	ID                    string        `json:"id"`
	Subreddit             string        `json:"subreddit"`
	Title                 template.HTML `json:"title"`
	SubredditNamePrefixed string        `json:"subreddit_name_prefixed"`
	URL                   string        `json:"url"`
	Ups                   int           `json:"ups"`
	Downs                 int           `json:"downs"`
	Score                 int           `json:"score"`
	Created               float64       `json:"created"`
	Selftext              string        `json:"selftext"`
	SelftextHTML          template.HTML `json:"selftext_html"`
	Thumbnail             string        `json:"thumbnail"`
	Permalink             string        `json:"permalink"`
	// Preview               RedditSubredditPreview `json:"preview"`
	NumComments int `json:"num_comments"`

	Preview struct {
		Enabled bool `json:"enabled"`
		Images  []struct {
			ID     string `json:"id"`
			Source struct {
				URL    string `json:"url"`
				Width  int    `json:"width"`
				Height int    `json:"height"`
			} `json:"source"`
		} `json:"images"`
	} `json:"preview"`

	// use
	PostHint  string `json:"post_hint"`
	Domain    string `json:"domain"`
	MediaOnly string `json:"media_only"`
}

func (r *RedditSubredditListing) CreatedTime() time.Time {
	return time.Unix(int64(r.Created), 0)
}

type RedditSubscriptionListing struct {
	Subreddit           string `json:"subreddit"`
	DisplayName         string `json:"display_name"`
	DisplayNamePrefixed string `json:"display_name_prefixed"`
	URL                 string `json:"url"`
	Title               string `json:"title"`
}

type RedditSubredditListingDataChild struct {
	Data RedditSubredditListing `json:"data"`
}

type RedditSubredditListingData struct {
	Before   string                            `json:"before"`
	After    string                            `json:"after"`
	Dist     int                               `json:"dist"`
	Children []RedditSubredditListingDataChild `json:"children"`
}

type RedditSubredditListingResponse struct {
	Kind string                     `json:"kind"`
	Data RedditSubredditListingData `json:"data"`
}

type RedditSubscriptionListingDataChild struct {
	Kind string                    `json:"kind"`
	Data RedditSubscriptionListing `json:"data"`
}

type RedditSubscriptionListingData struct {
	Before   string                               `json:"before"`
	After    string                               `json:"after"`
	Dist     int                                  `json:"dist"`
	Children []RedditSubscriptionListingDataChild `json:"children"`
}

type RedditSubscriptionListingResponse struct {
	Kind string                        `json:"kind"`
	Data RedditSubscriptionListingData `json:"data"`
}

func DoRefreshSubscriptions(token RedditToken, subs *RedditSubscriptionListingResponse) {
	log.Println("updating subscriptions")

	client := &http.Client{}
	req, _ := http.NewRequest("GET", redditSubredditsMineURL, nil)
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)
	req.Header.Add("User-Agent", userAgentDefault)

	q := req.URL.Query()
	q.Add("limit", "100")
	req.URL.RawQuery = q.Encode()

	resp, _ := client.Do(req)

	json.NewDecoder(resp.Body).Decode(&subs)
	log.Println("subscriptions update completed")
}

type SubscriptionViewModel struct {
	DisplayName string
	URL         string
	Title       string
	Selected    bool
}

func MakeSubscriptionsViewModel(selected string, redditSubscriptions RedditSubscriptionListingResponse) []SubscriptionViewModel {
	result := make([]SubscriptionViewModel, 0)
	for _, value := range redditSubscriptions.Data.Children {
		result = append(result, SubscriptionViewModel{
			DisplayName: value.Data.DisplayName,
			URL:         value.Data.URL,
			Title:       value.Data.Title,
			Selected:    value.Data.Title == selected,
		})
	}
	return result
}

type RedditUser struct {
	Name string `json:"name"`
}

func DoRefreshMe(token RedditToken, redditUser *RedditUser) {
	log.Println("updating user")
	client := &http.Client{}
	req, _ := http.NewRequest("GET", redditMeURL, nil)
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)
	req.Header.Add("User-Agent", userAgentDefault)
	resp, _ := client.Do(req)

	json.NewDecoder(resp.Body).Decode(&redditUser)
	log.Println("user update completed")
}

var indexTemplate string

func SubredditHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("subreddit handler")

	ctx := r.Context()
	token, _ := ctx.Value(redditTokenContextKey).(RedditToken)
	redditUser, userOk := ctx.Value(redditUserContextKey).(RedditUser)
	subscriptions, _ := ctx.Value(redditSubscriptionsContextKey).(RedditSubscriptionListingResponse)

	vars := mux.Vars(r)
	subreddit := vars["subreddit"]
	mainreddit := vars["mainreddit"]

	redditURL := token.BaseURL() + "/best.json"
	if mainreddit != "" {
		redditURL = token.BaseURL() + "/" + mainreddit + ".json"
	}

	if subreddit != "" {
		redditURL = token.BaseURL() + "/r/" + subreddit + ".json"
	}

	after := r.URL.Query().Get("after")
	client := &http.Client{}
	req, _ := http.NewRequest("GET", redditURL, nil)
	if token.TokenType != "" && token.AccessToken != "" {
		req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)
	}
	req.Header.Add("User-Agent", userAgentDefault)
	q := req.URL.Query()
	q.Add("limit", "100")
	if after != "" {
		q.Add("after", after)
	}
	req.URL.RawQuery = q.Encode()
	resp, rerr := client.Do(req)
	if rerr != nil {
		log.Errorln(resp.StatusCode)
		log.Errorln(rerr.Error())
	}
	var data RedditSubredditListingResponse
	json.NewDecoder(resp.Body).Decode(&data)

	var t *template.Template
	fmap := template.FuncMap{
		"url_decode": func(value string) string {
			return strings.ReplaceAll(value, "&amp;", "&")
		},
	}
	if indexTemplate != "" {
		t = template.Must(template.New("").Parse(indexTemplate))
	} else {
		// old style, read from templates
		t = template.Must(template.New("").Funcs(fmap).ParseGlob("templates/*.html"))
	}

	tc := TemplateContext{
		ListData:      data,
		Subscriptions: MakeSubscriptionsViewModel(subreddit, subscriptions),
		User:          redditUser,
		ProvideLogin:  redditConfig.RedditLoginPossible(),
		HasUser:       userOk,
		RedditToken:   token,
		OAuthURL:      "/reddit-login",
	}
	err := t.ExecuteTemplate(w, "index.html", tc)
	if err != nil {
		log.Errorln("error in template: ", err.Error())
	}
}

var redditConfig RedditConfig

func ProcessRedditUser(token RedditToken, session *sessions.Session, user *RedditUser) {
	userData := session.Values[redditUserSessionKey]
	if userData != nil {
		json.Unmarshal([]byte(userData.(string)), &user)
	} else {
		DoRefreshMe(token, user)
		j, _ := json.Marshal(user)
		session.Values[redditUserSessionKey] = string(j)
	}

}

func ProcessRedditSubscriptions(token RedditToken, session *sessions.Session, subs *RedditSubscriptionListingResponse) {
	subsData := session.Values[redditSubsSessionKey]
	if subsData != nil {
		json.Unmarshal([]byte(subsData.(string)), &subs)
	} else {
		DoRefreshSubscriptions(token, subs)
		j, _ := json.Marshal(subs)
		session.Values[redditSubsSessionKey] = string(j)
	}
}

func refreshRedditTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("entering reddit middleware")

		session, _ := r.Context().Value(sessionContextKey).(*sessions.Session)
		tokenJson, tokenOk := session.Values[redditTokenSessionKey].(string)
		var token RedditToken
		if tokenOk {
			json.Unmarshal([]byte(tokenJson), &token)
			log.Debugln("existing reddit session: ", token)
		} else {
			log.Debugln("no reddit token, creating anonymous.")
		}
		ctx := r.Context()

		if token.InUse() {
			if token.Expired() {
				DoRefreshToken(&token)
				j, _ := json.Marshal(token)
				session.Values[redditTokenSessionKey] = string(j)
			}

			var user RedditUser
			ProcessRedditUser(token, session, &user)
			ctx = context.WithValue(ctx, redditUserContextKey, user)

			var subs RedditSubscriptionListingResponse
			ProcessRedditSubscriptions(token, session, &subs)
			ctx = context.WithValue(ctx, redditSubscriptionsContextKey, subs)
		}

		ctx = context.WithValue(ctx, redditTokenContextKey, token)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type TemplateContext struct {
	ListData      RedditSubredditListingResponse
	Subscriptions []SubscriptionViewModel
	OAuthURL      string
	HasUser       bool
	User          RedditUser
	RedditToken   RedditToken
	ProvideLogin  bool
}

type OauthCallbackPayload struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

func redditOauthLogin(w http.ResponseWriter, r *http.Request) {

	log.Println("initiate login")

	uid := uuid.New()
	h := hash.New()
	h.Write([]byte(redditConfig.SecretKey))
	h.Write([]byte(uid.String()))
	state := hex.EncodeToString(h.Sum(nil))

	session, _ := r.Context().Value(sessionContextKey).(*sessions.Session)
	session.Values[redditStateSessionKey] = state

	oauthURL, _ := url.Parse(redditOAuthAuthorizeURL)
	q := oauthURL.Query()
	q.Add("client_id", redditConfig.ClientID)
	q.Add("response_type", "code")
	q.Add("state", state)
	q.Add("redirect_uri", redditConfig.OAuthCallback)
	q.Add("duration", "permanent")
	q.Add("scope", "identity read mysubreddits")
	oauthURL.RawQuery = q.Encode()

	log.Println("redirecting to reddit ", redditOAuthAuthorizeURL)

	session.Save(r, w)

	http.Redirect(w, r, oauthURL.String(), 302)

}

func redditOauthLogout(w http.ResponseWriter, r *http.Request) {

	token, tokenOk := r.Context().Value(redditTokenContextKey).(RedditToken)
	session, sessionOk := r.Context().Value(sessionContextKey).(*sessions.Session)

	if tokenOk {
		client := &http.Client{}
		values := url.Values{}
		values.Add("token", token.RefreshToken)
		values.Add("token_type_hint", "refresh_token")
		req, _ := http.NewRequest("POST", redditOAuthRevokeTokenURL, strings.NewReader(values.Encode()))
		client.Do(req)

	}

	if sessionOk {
		delete(session.Values, redditTokenSessionKey)
		delete(session.Values, redditUserContextKey)
		delete(session.Values, redditSubsSessionKey)
		delete(session.Values, redditStateSessionKey)
	}

	http.Redirect(w, r, "/", 302)
}

func oauthCallback(w http.ResponseWriter, r *http.Request) {

	log.Debugln("oauth callback")

	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")
	err := q.Get("error")

	session, _ := r.Context().Value(sessionContextKey).(*sessions.Session)

	originState := session.Values[redditStateSessionKey].(string)
	if state != originState {
		fmt.Fprintln(w, "error: states are not equal")
		return
	}

	if err != "" {
		fmt.Fprintln(w, "error:", err)
		return
	}

	client := &http.Client{}
	postData := url.Values{}
	postData.Add("grant_type", "authorization_code")
	postData.Add("code", code)
	postData.Add("redirect_uri", redditConfig.OAuthCallback)

	req, _ := http.NewRequest(
		"POST",
		redditAccessTokenURL,
		strings.NewReader(postData.Encode()),
	)
	req.SetBasicAuth(redditConfig.ClientID, redditConfig.ClientSecret)
	req.Header.Add("User-Agent", userAgentDefault)
	resp, _ := client.Do(req)
	var token RedditToken
	json.NewDecoder(resp.Body).Decode(&token)
	token.Created = time.Now()

	j, _ := json.Marshal(token)
	session.Values[redditTokenSessionKey] = string(j)

	delete(session.Values, redditStateSessionKey)

	session.Save(r, w)

	http.Redirect(w, r, "/", 302)

}

var sessionStore *sqlitestore.SqliteStore

func requestLogSeperatorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("-------------- REQUEST BEGIN ---------------")
		next.ServeHTTP(w, r)
		log.Println("-------------- REQUEST END   ---------------")
	})
}

func sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("entering session middleware")
		session, _ := sessionStore.Get(r, "session-name")
		// write to make sure the set cookie is set
		session.Save(r, w)
		session.Options.Secure = false
		session.Options.HttpOnly = false
		ctx := context.WithValue(r.Context(), sessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
		session.Save(r, w)
		log.Println("leavin session middleware. saved.")
	})
}

func setupDebugProxy() {
	// config to use mitmproxy for more details
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	os.Setenv("http_proxy", "http://localhost:3128/")
	os.Setenv("HTTP_PROXY", "http://localhost:3128/")
}

func defaultRedditConfig() RedditConfig {
	return RedditConfig{
		SecretKey:  "",
		Bind:       "127.0.0.1:8080",
		SessionsDB: "./session.db",
	}
}

func validateConfig() {
	// check for secret key
	if !redditConfig.HasSecretKey() {
		log.Warn("you do not use a secret key. please provide in config file (secret_key)")
	}

	if redditConfig.ClientID == "" {
		log.Warn("you do not use the client id. you cannot login. please provide in config file (client_id)")
	}

	if redditConfig.ClientSecret == "" {
		log.Warn("you do not use the client secret. you cannot login. please provide in config file (client_secert)")
	}

	if redditConfig.OAuthCallback == "" {
		log.Warn("you do not use the oauth callback. you cannot login. please provide in config file (oauth_callback)")
	}
}

func main() {

	// setupDebugProxy()

	log.SetFormatter(&log.TextFormatter{})
	log.SetLevel(log.DebugLevel)

	redditConfig = defaultRedditConfig()

	f, _ := os.Open("config.yml")
	defer f.Close()
	yaml.NewDecoder(f).Decode(&redditConfig)

	sessionStore, _ = sqlitestore.NewSqliteStore(
		redditConfig.SessionsDB,
		"sessions",
		"/",
		3600,
		[]byte(redditConfig.SecretKey),
	)

	validateConfig()

	r := mux.NewRouter()
	r.Use(sessionMiddleware)

	if redditConfig.RedditLoginPossible() {
		r.HandleFunc("/reddit-logout", redditOauthLogout)
		r.HandleFunc("/reddit-login", redditOauthLogin)
		r.HandleFunc("/oauth-callback", oauthCallback).Methods("GET")
	}

	redditSessionRoutes := r.PathPrefix("/").Subrouter()
	redditSessionRoutes.HandleFunc("/{mainreddit}", SubredditHandler)
	redditSessionRoutes.HandleFunc("/r/{subreddit}", SubredditHandler)
	redditSessionRoutes.HandleFunc("/r/{subreddit}/", SubredditHandler)
	redditSessionRoutes.HandleFunc("/", SubredditHandler)

	if redditConfig.RedditLoginPossible() {
		redditSessionRoutes.Use(refreshRedditTokenMiddleware)
	}

	http.Handle("/", r)

	log.Infoln("listening on ", redditConfig.Bind, "...")
	err := http.ListenAndServe(redditConfig.Bind, nil)
	if err != nil {
		log.Fatal(err)
	}

}
