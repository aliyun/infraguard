package reporter

import (
	"errors"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/models"
)

type brokenWriter struct{ err error }

func (w brokenWriter) Write([]byte) (int, error) { return 0, w.err }

func TestReportPropagatesOutputErrors(t *testing.T) {
	sentinel := errors.New("output failed")
	for _, format := range []string{"json", "html"} {
		t.Run(format, func(t *testing.T) {
			report := New(format, brokenWriter{err: sentinel})
			if err := report.Render([]models.FileResult{{File: "template.yaml"}}); !errors.Is(err, sentinel) {
				t.Fatalf("render error=%v", err)
			}
		})
	}
}

func TestUnknownSeverityIsPreserved(t *testing.T) {
	if got := localizeSeverity("custom", i18n.Msg()); got != "custom" {
		t.Fatalf("severity=%q", got)
	}
}
