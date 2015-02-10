package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"sync"

	"code.google.com/p/go-shlex"
)

var username = flag.String("username", "", "HE Certification Username")
var password = flag.String("password", "", "HE Certification Password")
var host = flag.String("host", "", "IPv6 hostname to be used (must be hostname and not IP!)")

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

func lookupIPv6(host string) (string, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if addr.To4() == nil {
			return addr.String(), nil
		}
	}
	return "", fmt.Errorf("Could not find IPv6 address for '%s'", host)
}

func main() {

	flag.Parse()

	if flag.NFlag() != 3 {
		fmt.Fprintf(os.Stderr, "Please specify all arguments")
		flag.Usage()
	}

	client, err := HELogin(*username, *password)
	if err != nil {
		log.Fatal(err)
	}

	ip, err := lookupIPv6(*host)
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	for _, test := range tests {
		wg.Add(1)
		go func(t dailyTest) {
			cmd := fmt.Sprintf(t.cmdFmt, *host, ip)
			log.Printf("Running test '%s' with cmd: %s", t.name, cmd)
			defer wg.Done()
			out, err := runCmd(cmd)
			if err != nil {
				log.Printf("Couldn't run command '%s': %s", cmd ,  err)
				return
			}
			log.Printf("Submitting '%s' to '%s'", t.name, t.formURL)

			v := url.Values{
				"input": []string{string(out)},
			}

			resp, err := client.PostForm(t.formURL, v)
			if err != nil {
				log.Printf("Could not submit '%s': %s", t.name, err)
				return
			}
			if resp.StatusCode != 200 {
				log.Printf("Could not submit '%s' got status '%s'", t.name, resp.Status)
				return
			}

		}(test)

	}
	wg.Wait()
}
