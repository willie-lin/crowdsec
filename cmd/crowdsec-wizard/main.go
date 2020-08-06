package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
)

var (
	actionPriority = map[int]string{
		0: "install_crowdsec_from_tgz",
		1: "upgrade_crowdsec",
		2: "detect_and_write_logs",
		3: "install_blockers",
		4: "uninstall_crowdsec",
		5: "exit_wizard",
	}

	menuAction = map[string]string{
		"install_crowdsec_from_tgz": "\n  (1) Install CrowdSec (from crowdsec-release.tgz)\n",
		"upgrade_crowdsec":          "(2) Upgrade CrowdSec\n",
		"detect_and_write_logs":     "(3) Detect Logs and install collections\n",
		"install_blockers":          "(4) Install blocker(s)\n",
		"uninstall_crowdsec":        "(5) Uninstall CrowdSec\n",
		"exit_wizard":               "(6) Exit wizard\n",
	}

	crowdsecConfig = map[string]string{
		"data_dir":  "/var/lib/crowdsec/data",
		"cscli_dir": "/etc/crowdsec/config/cscli/hub",
	}
)

func main() {
	cwhub.Cfgdir = filepath.Clean("/etc/crowdsec/config/cscli/")
	cwhub.Installdir = filepath.Clean("/etc/crowdsec/config/")
	cwhub.Hubdir = filepath.Clean("/etc/crowdsec/config/cscli/hub")
	for {
		err := Run()
		if err != nil {
			log.Fatalf("%s", err.Error())
		}
	}
}

func Run() error {
	menuChoice := make([]string, len(menuAction), len(menuAction))
	for i := 0; i < len(menuAction); i++ {
		menuChoice[i] = menuAction[actionPriority[i]]
	}

	var qs = []*survey.Question{
		{
			Name: "action",
			Prompt: &survey.Select{
				Message: "What do you want to do ?\n\n",
				Options: menuChoice,
				Default: "Install CrowdSec",
			},
		},
	}

	survey.MultilineQuestionTemplate = `
	{{- if .ShowHelp }}{{- color .Config.Icons.Help.Format }}{{ .Config.Icons.Help.Text }} {{ .Help }}{{color "reset"}}{{"\n"}}{{end}}
	{{- color .Config.Icons.Question.Format }}{{ .Config.Icons.Question.Text }} {{color "reset"}}
	{{- color "default+hb"}}{{ .Message }} {{color "reset"}}
	{{- if .ShowAnswer}}
	  {{- "\n"}}{{color "cyan"}}{{.Answer}}{{color "reset"}}
	  {{- if .Answer }}{{ "\n" }}{{ end }}
	{{- else }}
	  {{- if .Default}}{{color "white"}}({{.Default}}) {{color "reset"}}{{end}}
	  {{- color "cyan"}}[Enter 2 empty lines to finish]{{color "reset"}}
{{printf ""}}
	{{- end}}`

	menuResp := struct {
		Action string `survey:"color"`
	}{}

	err := survey.Ask(qs, &menuResp)
	if err == terminal.InterruptErr {
		return fmt.Errorf("Leaving cswizard. Bye o/")
	} else if err != nil {
		return err
	}
	reverseBack := make(map[string]string, len(menuAction))
	for id, action := range menuAction {
		reverseBack[action] = id
	}

	switch action := reverseBack[menuResp.Action]; action {
	case "install_crowdsec":
	case "upgrade_crowdsec":
	case "detect_and_write_logs":
		sd, err := NewServices()
		if err != nil {
			log.Fatalf(err.Error())
		}

		if err := sd.Run(); err != nil {
			log.Fatalf("error while detecting logs : %s", err)
		}

		if err := copyFile(acquisFilePath, fmt.Sprintf("%s/%s", cwhub.Installdir, acquisFilename)); err != nil {
			return fmt.Errorf("error while copying '%s' to '%s': %s", acquisFilePath, fmt.Sprintf("%s/%s", cwhub.Installdir, acquisFilename), err)
		}
		log.Printf("'%s' file deployed in '%s'", acquisFilePath, fmt.Sprintf("%s/%s", cwhub.Installdir, acquisFilename))
		if err := sd.installDependency(); err != nil {
			log.Fatalf("unable to install collection dependency : %s", err)
		}
	case "install_blockers":
	case "uninstall_crowdsec":
	case "exit_wizard":
		log.Printf("Leaving wizard. Bye o/")
		os.Exit(0)
	default:
		log.Fatalf("unknown action : '%s'", action)
	}
	return nil
}
