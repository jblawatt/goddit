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
	_ "github.com/gorilla/sessions"
	"github.com/michaeljs1990/sqlitestore"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	_ "runtime"
	"strings"
	"time"
)

const RedditAccessTokenURL = "https://www.reddit.com/api/v1/access_token"
const RedditSubredditsMineURL = "https://oauth.reddit.com/subreddits/mine"
const RedditMeURL = "https://oauth.reddit.com/api/v1/me"
const RedditOAuthAuthorizeURL = "https://www.reddit.com/api/v1/authorize"
const RedditOAuthRevokeTokenURL = "https://www.reddit.com/api/v1/revoke_token"

const RedditOAuthCallbackURL = "http://localhost:8080/oauth-callback"

const UserAgentDefault = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"

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
		return "https://oauth.reddit.com"
	} else {
		return "https://www.reddit.com"
	}
}

// END REDDIT TOKEN ---------------------------------

type RedditLoginConfig struct {
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	SecretKey    string `yaml:"secret_key"`
}

func DoRefreshToken(redditToken *RedditToken) {
	log.Println("refreshing token")
	client := &http.Client{}
	data := url.Values{}
	data.Add("grant_type", "refresh_token")
	data.Add("refresh_token", redditToken.AccessToken)

	request, _ := http.NewRequest("POST", RedditAccessTokenURL, strings.NewReader(data.Encode()))
	request.Header.Add("User-Agent", UserAgentDefault)
	request.SetBasicAuth(redditLoginConfig.ClientID, redditLoginConfig.ClientSecret)
	resp, _ := client.Do(request)
	json.NewDecoder(resp.Body).Decode(&redditToken)
	redditToken.Created = time.Now()
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
	Subreddit             string                 `json:"subreddit"`
	Title                 template.HTML          `json:"title"`
	SubredditNamePrefixed string                 `json:"subreddit_name_prefixed"`
	URL                   string                 `json:"url"`
	Ups                   int                    `json:"ups"`
	Downs                 int                    `json:"downs"`
	Score                 int                    `json:"score"`
	Created               float64                `json:"created"`
	Selftext              string                 `json:"selftext"`
	SelftextHTML          template.HTML          `json:"selftext_html"`
	Thumbnail             string                 `json:"thumbnail"`
	Permalink             string                 `json:"permalink"`
	Preview               RedditSubredditPreview `json:"preview"`
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
	log.Println("refreshing subscriptions")

	client := &http.Client{}
	req, _ := http.NewRequest("GET", RedditSubredditsMineURL, nil)
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)
	req.Header.Add("User-Agent", UserAgentDefault)

	q := req.URL.Query()
	q.Add("limit", "100")
	req.URL.RawQuery = q.Encode()

	resp, _ := client.Do(req)

	json.NewDecoder(resp.Body).Decode(&subs)
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
	client := &http.Client{}
	req, _ := http.NewRequest("GET", RedditMeURL, nil)
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)
	req.Header.Add("User-Agent", UserAgentDefault)
	resp, _ := client.Do(req)

	json.NewDecoder(resp.Body).Decode(&redditUser)
}

func SubredditHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("subreddit handler")

	ctx := r.Context()
	token, _ := ctx.Value("token").(RedditToken)
	redditUser, userOk := ctx.Value("redditUser").(RedditUser)
	subscriptions, subsOk := ctx.Value("redditSubscriptions").(RedditSubscriptionListingResponse)
	vars := mux.Vars(r)
	subreddit := vars["subreddit"]
	mainreddit := vars["mainreddit"]

	url := token.BaseURL() + "/best.json"
	if mainreddit != "" {
		url = token.BaseURL() + "/" + mainreddit + ".json"
	}

	if subreddit != "" {
		url = token.BaseURL() + "/r/" + subreddit + ".json"
	}

	after := r.URL.Query().Get("after")
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)
	req.Header.Add("User-Agent", UserAgentDefault)

	q := req.URL.Query()
	q.Add("limit", "100")
	if after != "" {
		q.Add("after", after)
	}
	req.URL.RawQuery = q.Encode()
	resp, _ := client.Do(req)
	var data RedditSubredditListingResponse
	json.NewDecoder(resp.Body).Decode(&data)
	t := template.Must(template.ParseGlob("templates/*.html"))

	if !subsOk {
		subscriptions = RedditSubscriptionListingResponse{}
	}

	tc := TemplateContext{
		ListData:      data,
		Subscriptions: MakeSubscriptionsViewModel(subreddit, subscriptions),
		User:          redditUser,
		HasUser:       userOk,
		RedditToken:   token,
		OAuthURL:      "/reddit-login",
	}
	err := t.Execute(w, &tc)
	if err != nil {
		log.Println(err.Error())
	}
}

var redditLoginConfig RedditLoginConfig

func refreshRedditTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("entering reddit middleware")

		session, _ := sessionStore.Get(r, "session-name")
		token, tokenOk := session.Values["token"].(RedditToken)
		if !tokenOk {
			token = RedditToken{}
		}
		inUse := token.InUse()
		// fixme: not allways refresh
		// expired := token.Expired()
		ctx := r.Context()

		if inUse {
			log.Println("updating token")
			DoRefreshToken(&token)
			session.Values["token"] = token
			session.Save(r, w)

			var user RedditUser
			DoRefreshMe(token, &user)
			ctx = context.WithValue(ctx, "redditUser", user)

			var subs RedditSubscriptionListingResponse
			DoRefreshSubscriptions(token, &subs)
			ctx = context.WithValue(ctx, "redditSubscriptions", subs)
		}

		ctx = context.WithValue(ctx, "token", token)

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
}

type OauthCallbackPayload struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

func redditOauthInitiate(w http.ResponseWriter, r *http.Request) {

	log.Println("initiate login")

	uid := uuid.New()
	h := hash.New()
	h.Write([]byte(redditLoginConfig.SecretKey))
	h.Write([]byte(uid.String()))
	state := hex.EncodeToString(h.Sum(nil))

	session, _ := sessionStore.Get(r, "session-name")
	session.Values["redditState"] = state
	session.Save(r, w)

	oauthURL, _ := url.Parse(RedditOAuthAuthorizeURL)
	q := oauthURL.Query()
	q.Add("client_id", redditLoginConfig.ClientID)
	q.Add("response_type", "code")
	q.Add("state", state)
	q.Add("redirect_uri", RedditOAuthCallbackURL)
	q.Add("duration", "permanent")
	q.Add("scope", "identity read mysubreddits")
	oauthURL.RawQuery = q.Encode()

	http.Redirect(w, r, oauthURL.String(), 303)

}

func redditOauthLogout(w http.ResponseWriter, r *http.Request) {

	session, _ := sessionStore.Get(r, "session-name")
	token, tokenOk := session.Values["token"].(RedditToken)

	if tokenOk {
		client := &http.Client{}
		values := url.Values{}
		values.Add("token", token.RefreshToken)
		values.Add("token_type_hint", "refresh_token")
		req, _ := http.NewRequest("POST", RedditOAuthRevokeTokenURL, strings.NewReader(values.Encode()))
		client.Do(req)
	}

	delete(session.Values, "token")

	session.Save(r, w)

	http.Redirect(w, r, "/", 303)
}

func oauthCallback(w http.ResponseWriter, r *http.Request) {

	log.Println("oauth callback")

	// fixme: error

	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")

	session, _ := sessionStore.Get(r, "session-name")
	originState := session.Values["redditState"].(string)
	if state != originState {
		fmt.Fprintln(w, "error: states are not equal")
		return
	}

	client := &http.Client{}
	postData := url.Values{}
	postData.Add("grant_type", "authorization_code")
	postData.Add("code", code)
	postData.Add("redirect_uri", RedditOAuthCallbackURL)

	req, _ := http.NewRequest(
		"POST",
		RedditAccessTokenURL,
		strings.NewReader(postData.Encode()),
	)
	req.SetBasicAuth(redditLoginConfig.ClientID, redditLoginConfig.ClientSecret)
	req.Header.Add("User-Agent", UserAgentDefault)
	resp, _ := client.Do(req)
	var token RedditToken
	json.NewDecoder(resp.Body).Decode(&token)
	token.Created = time.Now()

	session.Values["token"] = token

	session.Save(r, w)
	http.Redirect(w, r, "/", 303)

}

var sessionStore *sqlitestore.SqliteStore

func main() {

	// config to use mitmproxy for more details
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	os.Setenv("http_proxy", "http://localhost:3128/")
	os.Setenv("HTTP_PROXY", "http://localhost:3128/")

	f, _ := os.Open("config.yml")
	defer f.Close()
	yaml.NewDecoder(f).Decode(&redditLoginConfig)

	// redditToken = login()
	// redditSubscriptions = GetSubscribtions(redditToken)

	sessionStore, _ = sqlitestore.NewSqliteStore("./session.db", "sessions", "/", 3600, []byte(redditLoginConfig.SecretKey))

	r := mux.NewRouter()
	r.Use(refreshRedditTokenMiddleware)
	r.HandleFunc("/reddit-logout", redditOauthLogout)
	r.HandleFunc("/reddit-login", redditOauthInitiate)
	r.HandleFunc("/oauth-callback", oauthCallback).Methods("GET")
	r.HandleFunc("/{mainreddit}", SubredditHandler)
	r.HandleFunc("/r/{subreddit}", SubredditHandler)
	r.HandleFunc("/r/{subreddit}/", SubredditHandler)
	r.HandleFunc("/", SubredditHandler)
	http.Handle("/", r)
	http.ListenAndServe("127.0.0.1:8080", nil)

}
