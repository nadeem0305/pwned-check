// Command pwned-check tells you how many times a password appears in known breaches,
// using the Have I Been Pwned range API. Only the first 5 hex characters of the
// password's SHA-1 hash leave your machine (k-anonymity).
package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

func main() {
	pw, err := readPassword()
	if err != nil || pw == "" {
		fmt.Fprintln(os.Stderr, "no password given")
		os.Exit(2)
	}
	n, err := check(pw, "https://api.pwnedpasswords.com/range/")
	if err != nil {
		fmt.Fprintln(os.Stderr, "lookup failed:", err)
		os.Exit(2)
	}
	if n == 0 {
		fmt.Println("Not found in any known breach.")
		return
	}
	fmt.Printf("Found %d times in breaches. Don't use it.\n", n)
	os.Exit(1)
}

// readPassword reads without echo from a terminal, or the first line of piped stdin.
func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func check(pw, baseURL string) (int, error) {
	sum := fmt.Sprintf("%X", sha1.Sum([]byte(pw)))
	prefix, suffix := sum[:5], sum[5:]

	req, err := http.NewRequest("GET", baseURL+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Add-Padding", "true") // hides the real response size from observers
	req.Header.Set("User-Agent", "pwned-check")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return findCount(resp.Body, suffix)
}

// findCount scans "SUFFIX:COUNT" lines; padding entries have count 0.
func findCount(r io.Reader, suffix string) (int, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		hash, count, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && strings.EqualFold(hash, suffix) {
			return strconv.Atoi(count)
		}
	}
	return 0, sc.Err()
}
