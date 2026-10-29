package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/config"
	"github.com/aliyun/infraguard/pkg/i18n"
)

func TestParseLangFlag(t *testing.T) {
	originalArgs, originalLang := os.Args, globalLang
	t.Cleanup(func() { os.Args, globalLang = originalArgs, originalLang })
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"infraguard", "scan", "--lang", "zh"}, "zh"},
		{[]string{"infraguard", "--lang=fr"}, "fr"},
		{[]string{"infraguard", "--lang"}, ""},
		{[]string{"infraguard", "scan"}, ""},
	} {
		globalLang = ""
		os.Args = tc.args
		parseLangFlag()
		if globalLang != tc.want {
			t.Errorf("%v: got %q want %q", tc.args, globalLang, tc.want)
		}
	}
}

func TestExecuteLocalizedHelp(t *testing.T) {
	oldArgs, oldLang := os.Args, globalLang
	oldLanguage := i18n.GetLanguage()
	t.Cleanup(func() {
		os.Args, globalLang = oldArgs, oldLang
		i18n.SetLanguage(oldLanguage)
		setUsageTemplate()
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
	})
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	var output bytes.Buffer
	rootCmd.SetOut(&output)
	rootCmd.SetArgs([]string{"--help"})
	os.Args = []string{"infraguard", "--lang=en", "--help"}
	globalLang = ""
	if err := Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "infraguard") || !strings.Contains(output.String(), "scan") {
		t.Fatalf("unexpected help: %s", output.String())
	}
}

func TestExecuteUsesSavedLanguage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := config.Save(&config.Config{Lang: "zh"}); err != nil {
		t.Fatal(err)
	}
	oldArgs, oldLang, oldLanguage := os.Args, globalLang, i18n.GetLanguage()
	t.Cleanup(func() {
		os.Args, globalLang = oldArgs, oldLang
		i18n.SetLanguage(oldLanguage)
		setUsageTemplate()
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
	})
	os.Args = []string{"infraguard"}
	globalLang = ""
	rootCmd.SetArgs([]string{"--help"})
	rootCmd.SetOut(&bytes.Buffer{})
	if err := Execute(); err != nil {
		t.Fatal(err)
	}
	if i18n.GetLanguage() != "zh-CN" {
		t.Fatalf("saved language ignored: %s", i18n.GetLanguage())
	}
}

func TestCompletionCommandsGenerateShellScripts(t *testing.T) {
	updateCommandDescriptions()
	completion, _, err := rootCmd.Find([]string{"completion"})
	if err != nil || completion == nil {
		t.Fatalf("completion command: %v", err)
	}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "completion")
			if err != nil {
				t.Fatal(err)
			}
			old := os.Stdout
			os.Stdout = file
			t.Cleanup(func() { os.Stdout = old; file.Close() })
			completion.Run(completion, []string{shell})
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(file.Name())
			if err != nil || len(data) == 0 || !bytes.Contains(data, []byte("infraguard")) {
				t.Fatalf("empty completion output for %s: %v", shell, err)
			}
		})
	}
}

func TestHelpCommandKnownAndUnknownTopics(t *testing.T) {
	updateCommandDescriptions()
	rootCmd.InitDefaultHelpCmd()
	help, _, err := rootCmd.Find([]string{"help"})
	if err != nil || help == nil {
		t.Fatalf("help command: %v", err)
	}
	var output bytes.Buffer
	rootCmd.SetOut(&output)
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.RemoveCommand(help) })
	help.Run(help, []string{"scan"})
	if !strings.Contains(output.String(), "scan") {
		t.Fatalf("missing scan help: %s", output.String())
	}
	output.Reset()
	help.Run(help, []string{"nonexistent-command-for-test"})
	if !strings.Contains(output.String(), "nonexistent-command-for-test") {
		t.Fatalf("missing unknown topic: %s", output.String())
	}
}
