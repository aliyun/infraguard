package ros

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	sdk "github.com/alibabacloud-go/ros-20190910/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

func TestPreviewStackWithLocalAPI(t *testing.T) {
	type requestData struct {
		action string
		params string
	}
	requests := make(chan requestData, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("x-acs-action")
		if action == "" {
			action = r.URL.Query().Get("Action")
		}
		_ = r.ParseForm()
		requests <- requestData{action: action, params: fmt.Sprint(r.Form)}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Stack":{"Resources":[{"LogicalResourceId":"Vpc","ResourceType":"ALIYUN::ECS::VPC","Properties":{"Name":"sample"},"RequiredBy":["Instance"]}]}}`)
	}))
	defer srv.Close()
	client, err := sdk.NewClient(&openapi.Config{AccessKeyId: tea.String("test-id"), AccessKeySecret: tea.String("test-secret"), Endpoint: tea.String(strings.TrimPrefix(srv.URL, "http://")), Protocol: tea.String("HTTP")})
	if err != nil {
		t.Fatal(err)
	}
	req := &PreviewStackRequest{Region: "cn-test", TemplateBody: `{"Resources":{}}`, Parameters: map[string]interface{}{"s": "text", "n": 2, "b": true, "j": map[string]interface{}{"x": 1}}}
	result, err := CallPreviewStack(client, req)
	if err != nil {
		t.Fatal(err)
	}
	request := <-requests
	if request.action != "PreviewStack" {
		t.Fatalf("action %q", request.action)
	}
	for _, expected := range []string{"text", "true", `{"x":1}`} {
		if !strings.Contains(request.params, expected) {
			t.Errorf("missing parameter %q in %s", expected, request.params)
		}
	}
	if result.Stack == nil || len(result.Stack.Resources) != 1 || result.Stack.Resources[0].LogicalResourceId != "Vpc" || len(result.Stack.Resources[0].DependsOn) != 1 {
		data, _ := json.Marshal(result)
		t.Fatalf("result %s", data)
	}
	if _, err := CallPreviewStack(client, &PreviewStackRequest{Parameters: map[string]interface{}{"bad": make(chan int)}}); err == nil {
		t.Fatal("unmarshalable parameter accepted")
	}
	if _, err := CallPreviewStack(nil, req); err == nil {
		t.Fatal("nil client accepted")
	}
}

func TestSDKErrorTranslation(t *testing.T) {
	for _, code := range []string{"InvalidAccessKeyId.NotFound", "SignatureDoesNotMatch", "Forbidden.RAM", "Throttling.User", "ServiceUnavailable", "TemplateValidationError", "Other"} {
		sdkErr := &tea.SDKError{Code: tea.String(code), Message: tea.String("failure"), StatusCode: tea.Int(400), Data: tea.String(`{"RequestId":"req-test"}`)}
		got := handleAPIError(sdkErr)
		if got == nil {
			t.Errorf("%s: nil error", code)
			continue
		}
		if code == "TemplateValidationError" || code == "Other" {
			formatted, ok := got.(*FormattedAPIError)
			if !ok || formatted.RequestID != "req-test" || formatted.Code != code {
				t.Errorf("%s: %#v", code, got)
			}
		}
	}
}

func TestPreviewResponseHandlesMissingAndNilResources(t *testing.T) {
	for _, response := range []*sdk.PreviewStackResponse{nil, {}, {Body: &sdk.PreviewStackResponseBody{}}} {
		if _, err := parsePreviewStackResponse(response); err == nil {
			t.Fatal("empty API response accepted")
		}
	}
	var response sdk.PreviewStackResponse
	if err := json.Unmarshal([]byte(`{"body":{"Stack":{"Resources":[null,{"LogicalResourceId":"Vpc","ResourceType":"ALIYUN::ECS::VPC"}]}}}`), &response); err != nil {
		t.Fatal(err)
	}
	got, err := parsePreviewStackResponse(&response)
	if err != nil || got.Stack == nil || len(got.Stack.Resources) != 1 || got.Stack.Resources[0].LogicalResourceId != "Vpc" {
		t.Fatalf("preview: %+v %v", got, err)
	}
	converted, err := ConvertPreviewToTemplate(&PreviewStackResponse{Stack: &StackInfo{Resources: []*ResourceInfo{nil, {LogicalResourceId: ""}, {LogicalResourceId: "Vpc", ResourceType: "ALIYUN::ECS::VPC"}}}})
	if err != nil || len(converted["Resources"].(map[string]interface{})) != 1 {
		t.Fatalf("converted: %+v %v", converted, err)
	}
}
