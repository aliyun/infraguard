package schema

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ros "github.com/alibabacloud-go/ros-20190910/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

func TestParseResourceSchema(t *testing.T) {
	p := parsePropertyValue(map[string]interface{}{
		"Type": "Map", "Required": true, "Immutable": true, "Description": "example",
		"Constraints": []interface{}{
			"invalid", map[string]interface{}{"CustomConstraint": "ignored"},
			map[string]interface{}{"AllowedValues": []interface{}{"a", "b"}, "AllowedPattern": "^a", "Range": map[string]interface{}{"Min": 1, "Max": float64(4)}, "Length": map[string]interface{}{"Min": float32(2), "Max": int64(8)}},
		},
		"Schema": map[string]interface{}{"*": map[string]interface{}{"Schema": map[string]interface{}{"Name": map[string]interface{}{"Type": "String"}, "bad": false}}},
	})
	if p == nil || p.Type != "Map" || !p.Required || p.Updatable || p.Description != "example" {
		t.Fatalf("unexpected property: %#v", p)
	}
	c := p.Constraints
	if c == nil || len(c.AllowedValues) != 2 || c.AllowedPattern != "^a" || *c.MinValue != 1 || *c.MaxValue != 4 || *c.MinLength != 2 || *c.MaxLength != 8 {
		t.Fatalf("unexpected constraints: %#v", c)
	}
	if len(p.Properties) != 1 || p.Properties["Name"].Type != "String" || !p.Properties["Name"].Updatable {
		t.Fatalf("unexpected nested properties: %#v", p.Properties)
	}
	if parsePropertyValue("bad") != nil || parseAttributeValue(42) != nil {
		t.Fatal("invalid schema values accepted")
	}
	if a := parseAttributeValue(map[string]interface{}{"Description": "output"}); a == nil || a.Description != "output" {
		t.Fatalf("unexpected attribute: %#v", a)
	}
	if parseConstraints([]interface{}{map[string]interface{}{"CustomConstraint": "x"}, 1}) != nil {
		t.Fatal("empty constraints should be nil")
	}
	if parseSchemaProperties(map[string]interface{}{"*": "invalid", "bad": 1}) != nil {
		t.Fatal("invalid schema should be nil")
	}
}

func TestParseConstraintNumericRepresentations(t *testing.T) {
	for _, tc := range []struct {
		name     string
		min, max interface{}
	}{
		{"float32", float32(2), float32(8)},
		{"float64", float64(2), float64(8)},
		{"int", int(2), int(8)},
		{"int64", int64(2), int64(8)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			constraints := parseConstraints([]interface{}{map[string]interface{}{
				"Range":  map[string]interface{}{"Min": tc.min, "Max": tc.max},
				"Length": map[string]interface{}{"Min": tc.min, "Max": tc.max},
			}})
			if constraints == nil || constraints.MinValue == nil || *constraints.MinValue != 2 || constraints.MaxValue == nil || *constraints.MaxValue != 8 || constraints.MinLength == nil || *constraints.MinLength != 2 || constraints.MaxLength == nil || *constraints.MaxLength != 8 {
				t.Fatalf("numeric constraints: %+v", constraints)
			}
		})
	}
	if got := parseConstraints([]interface{}{map[string]interface{}{"Range": map[string]interface{}{"Min": "bad"}, "Length": map[string]interface{}{"Max": true}}}); got != nil {
		t.Fatalf("invalid numeric bounds: %+v", got)
	}
}

func TestFetchAndSaveWithLocalROS(t *testing.T) {
	requests := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("x-acs-action")
		if action == "" {
			action = r.URL.Query().Get("Action")
		}
		requests[action]++
		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "ListResourceTypes":
			fmt.Fprint(w, `{"ResourceTypes":["ALIYUN::TEST::Two","ALIYUN::TEST::One"]}`)
		case "GetResourceType":
			fmt.Fprint(w, `{"Description":"test resource","Properties":{"Name":{"Type":"String","Required":true}},"Attributes":{"Id":{"Description":"identifier"}}}`)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	client, err := ros.NewClient(&openapi.Config{AccessKeyId: tea.String("test-id"), AccessKeySecret: tea.String("test-secret"), Endpoint: tea.String(strings.TrimPrefix(srv.URL, "http://")), Protocol: tea.String("HTTP")})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "schema.json")
	count, err := FetchAndSave(client, &FetchOptions{OutputPath: path, Logger: func(string, ...interface{}) {}})
	if err != nil || count != 2 {
		t.Fatalf("fetch count %d: %v requests=%v", count, err, requests)
	}
	loaded := loadExistingSchema(path)
	if loaded == nil || loaded.ResourceTypes["ALIYUN::TEST::One"].Properties["Name"].Type != "String" || loaded.ResourceTypes["ALIYUN::TEST::Two"].Attributes["Id"].Description != "identifier" {
		t.Fatalf("saved schema: %+v", loaded)
	}
	count, err = FetchAndSave(client, &FetchOptions{OutputPath: path, Logger: func(string, ...interface{}) {}})
	if err != nil || count != 2 || requests["GetResourceType"] != 2 {
		t.Fatalf("fresh resources should be skipped: count=%d err=%v requests=%v", count, err, requests)
	}
}

func TestSchemaPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.json")
	if loadExistingSchema(path) != nil {
		t.Fatal("missing file should be ignored")
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if loadExistingSchema(path) != nil {
		t.Fatal("invalid JSON should be ignored")
	}
	if err := os.WriteFile(path, []byte(`{"version":"v1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded := loadExistingSchema(path)
	if loaded == nil || loaded.ResourceTypes == nil {
		t.Fatal("resource map was not initialized")
	}
	loaded.ResourceTypes["Example"] = &ResourceType{Description: "hello"}
	if err := saveSchema(loaded, path); err != nil {
		t.Fatal(err)
	}
	if got := loadExistingSchema(path); got == nil || got.ResourceTypes["Example"].Description != "hello" {
		t.Fatalf("round trip failed: %#v", got)
	}
	if err := saveSchema(loaded, filepath.Join(path, "bad")); err == nil {
		t.Fatal("expected write error")
	}
}

func TestThrottlingClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.New("Throttling: retry"), true}, {errors.New("other"), false},
		{&tea.SDKError{Code: tea.String("Throttling.User")}, true}, {&tea.SDKError{Code: tea.String("Forbidden")}, false},
	} {
		if got := isThrottlingError(tc.err); got != tc.want {
			t.Errorf("%v: got %v want %v", tc.err, got, tc.want)
		}
	}
}

func TestFetchAndSaveListFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"Code":"Forbidden","Message":"access denied"}`)
	}))
	defer srv.Close()
	client, err := ros.NewClient(&openapi.Config{AccessKeyId: tea.String("test-id"), AccessKeySecret: tea.String("test-secret"), Endpoint: tea.String(strings.TrimPrefix(srv.URL, "http://")), Protocol: tea.String("HTTP")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FetchAndSave(client, &FetchOptions{OutputPath: filepath.Join(t.TempDir(), "schema.json")}); err == nil || !strings.Contains(err.Error(), "list resource types") {
		t.Fatalf("expected list error, got %v", err)
	}
}

func TestFetchAndSaveSkipsResourceErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("x-acs-action")
		if action == "" {
			action = r.URL.Query().Get("Action")
		}
		w.Header().Set("Content-Type", "application/json")
		if action == "ListResourceTypes" {
			fmt.Fprint(w, `{"ResourceTypes":["ALIYUN::TEST::Bad"]}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"Code":"Forbidden","Message":"access denied"}`)
	}))
	defer srv.Close()
	client, err := ros.NewClient(&openapi.Config{AccessKeyId: tea.String("test-id"), AccessKeySecret: tea.String("test-secret"), Endpoint: tea.String(strings.TrimPrefix(srv.URL, "http://")), Protocol: tea.String("HTTP")})
	if err != nil {
		t.Fatal(err)
	}
	var logs []string
	count, err := FetchAndSave(client, &FetchOptions{OutputPath: filepath.Join(t.TempDir(), "schema.json"), Logger: func(format string, args ...interface{}) { logs = append(logs, fmt.Sprintf(format, args...)) }})
	if err != nil || count != 0 || !strings.Contains(strings.Join(logs, "\n"), "failed to get ALIYUN::TEST::Bad") {
		t.Fatalf("count=%d err=%v logs=%v", count, err, logs)
	}
}

func TestFetchWithRetryRecoversFromThrottling(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"Code":"Throttling.User","Message":"slow down"}`)
			return
		}
		fmt.Fprint(w, `{"Description":"recovered","Properties":{"Name":{"Type":"String"}}}`)
	}))
	defer srv.Close()
	client, err := ros.NewClient(&openapi.Config{AccessKeyId: tea.String("test-id"), AccessKeySecret: tea.String("test-secret"), Endpoint: tea.String(strings.TrimPrefix(srv.URL, "http://")), Protocol: tea.String("HTTP")})
	if err != nil {
		t.Fatal(err)
	}
	result, err := fetchWithRetry(client, "ALIYUN::TEST::Resource", &FetchOptions{Logger: func(string, ...interface{}) {}})
	if err != nil || result.Description != "recovered" || calls != 2 {
		t.Fatalf("retry: calls=%d result=%+v err=%v", calls, result, err)
	}
}

func TestRegistryLoadPrefersValidLocalSchema(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	r := &Registry{}
	if err := r.Load(); err != nil || r.ResourceTypeCount() == 0 {
		t.Fatalf("embedded schema: %v, count %d", err, r.ResourceTypeCount())
	}
	local := []byte(`{"version":"local","resourceTypes":{"ALIYUN::TEST::Widget":{"description":"local data"}}}`)
	if err := SaveLocal(local); err != nil {
		t.Fatal(err)
	}
	if err := r.Load(); err != nil || r.Version() != "local" || r.GetResourceType("ALIYUN::TEST::Widget") == nil {
		t.Fatalf("local schema: version=%q err=%v", r.Version(), err)
	}
	if err := SaveLocal([]byte("invalid")); err != nil {
		t.Fatal(err)
	}
	if err := r.Load(); err != nil || r.ResourceTypeCount() == 0 || r.Version() == "local" {
		t.Fatalf("embedded fallback: version=%q err=%v", r.Version(), err)
	}
}

func TestFetchAndSaveReportsSaveFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("x-acs-action") == "ListResourceTypes" || r.URL.Query().Get("Action") == "ListResourceTypes" {
			fmt.Fprint(w, `{"ResourceTypes":["ALIYUN::TEST::One"]}`)
		} else {
			fmt.Fprint(w, `{"Description":"resource"}`)
		}
	}))
	defer srv.Close()
	client, err := ros.NewClient(&openapi.Config{AccessKeyId: tea.String("test-id"), AccessKeySecret: tea.String("test-secret"), Endpoint: tea.String(strings.TrimPrefix(srv.URL, "http://")), Protocol: tea.String("HTTP")})
	if err != nil {
		t.Fatal(err)
	}
	var logs []string
	path := filepath.Join(t.TempDir(), "missing", "schema.json")
	count, err := FetchAndSave(client, &FetchOptions{OutputPath: path, Logger: func(format string, args ...interface{}) { logs = append(logs, fmt.Sprintf(format, args...)) }})
	if err != nil || count != 1 || !strings.Contains(strings.Join(logs, "\n"), "failed to save schema") {
		t.Fatalf("count=%d err=%v logs=%v", count, err, logs)
	}
}
