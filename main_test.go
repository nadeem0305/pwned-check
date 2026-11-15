package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheck(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n")
	}))
	defer srv.Close()

	n, err := check("password", srv.URL+"/range/")
	if err != nil || n != 42 {
		t.Fatalf("got %d, %v; want 42", n, err)
	}
	if gotPath != "/range/5BAA6" {
		t.Errorf("sent %q; only the 5-char prefix should leave the machine", gotPath)
	}
	if n, _ := check("not-in-list", srv.URL+"/range/"); n != 0 {
		t.Errorf("unlisted password got %d", n)
	}
}
