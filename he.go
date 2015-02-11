package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"time"

	"code.google.com/p/go-shlex"
	"github.com/golang/glog"
)

var username = flag.String("username", "", "HE Certification Username")
var password = flag.String("password", "", "HE Certification Password")
var dryrun = flag.Bool("dryrun", false, "Don't submit to HE")

func init() {
	rand.Seed(time.Now().Unix())
}

func HELogin(user, pass string) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	c := &http.Client{
		Jar: jar,
	}

	v := url.Values{
		"f_user": []string{user},
		"f_pass": []string{pass},
	}

	resp, err := c.PostForm("https://ipv6.he.net//certification/login.php", v)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Failed to login.  Got '%s response.", resp.Status)
	}

	u, _ := url.Parse("https://ipv6.he.net/")
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == "PHPSESSID" {
			return c, nil
		}
	}

	return nil, fmt.Errorf("Failed to login. Couldn't find a session ID in response")
}

func runCmd(cl string) ([]byte, error) {
	c, err := shlex.Split(cl)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(c[0], c[1:]...)
	return cmd.CombinedOutput()
}

type dailyTest struct {
	name    string
	cmdFmt  string
	formURL string
}

var tests = []dailyTest{
	{
		name:    "traceroute6",
		cmdFmt:  "traceroute6 -n %[1]s",
		formURL: "https://ipv6.he.net/certification/daily.php?test=traceroute",
	},
	{
		name:    "dig aaaa",
		cmdFmt:  "dig @8.8.8.8 AAAA %[1]s",
		formURL: "https://ipv6.he.net/certification/daily.php?test=aaaa",
	},
	{
		name:    "dig ptr",
		cmdFmt:  "dig @8.8.8.8 -x %[2]s",
		formURL: "https://ipv6.he.net/certification/daily.php?test=ptr",
	},
	{
		name:    "ping6",
		cmdFmt:  "ping6 -n -c4 %[1]s",
		formURL: "https://ipv6.he.net/certification/daily.php?test=ping",
	},
	{
		name:    "whois",
		cmdFmt:  `whois -h whois.arin.net "n %[2]s"`,
		formURL: "https://ipv6.he.net/certification/daily.php?test=whois",
	},
}

func randomSite() *ipv6Site {
	r := rand.Intn(len(v6Sites) - 1)
	return &v6Sites[r]
}

func isAlive(ip string) bool {
	cmd := exec.Command("ping6", "-c1", ip)
	if err := cmd.Start(); err == nil {
		return true
	}
	return false
}

func main() {

	flag.Parse()

	if *username == "" || *password == "" {
		fmt.Fprintf(os.Stderr, "Please specify username and password arguments\n\n")
		flag.Usage()
		os.Exit(1)
	}

	client, err := HELogin(*username, *password)
	if err != nil {
		glog.Fatal(err)
	}

	var site *ipv6Site
	for i := 0; i <= 25; i++ {
		site = randomSite()
		glog.Infof("Found site '%s'.  Testing to see if alive.", site.host)
		if isAlive(site.addr) {
			break
		}
		glog.Info("Site '%s' was not alive. Skipping,", site.host)
	}
	glog.Infof("Found random v6 site '%s', '%s'", site.host, site.addr)

	var wg sync.WaitGroup
	for _, test := range tests {
		wg.Add(1)
		go func(t dailyTest) {
			cmd := fmt.Sprintf(t.cmdFmt, site.host, site.addr)
			glog.Infof("Running '%s' with cmd ''%s'", t.name, cmd)
			defer wg.Done()
			out, err := runCmd(cmd)
			if err != nil {
				glog.Infof("Failed to run cmd '%s'", cmd)
				glog.Info(string(out))
				glog.Fatal(err)
				return
			}

			glog.Infof("Command output for '%s'", t.name)
			glog.Info(string(out))

			var dryrunLog string
			if *dryrun {
				dryrunLog = "DRYRUN -- "
			}

			glog.Infof("%sSubmitting '%s' to '%s'", dryrunLog, t.name, t.formURL)

			if !*dryrun {
				v := url.Values{
					"input": []string{string(out)},
				}

				resp, err := client.PostForm(t.formURL, v)
				if err != nil {
					glog.Errorf("Could not submit '%s': %s", t.name, err)
					return
				}
				if resp.StatusCode != 200 {
					glog.Errorf("Could not submit '%s' got status '%s'", t.name, resp.Status)
					return
				}

			}
		}(test)

	}
	wg.Wait()
}
