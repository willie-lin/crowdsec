package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	log.Printf("Survey : %+v \n", survey.MultilineQuestionTemplate)
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
		err = sd.Detect()
		if err != nil {
			log.Fatalf(err.Error())
		}
		log.Printf("detected %d services", len(sd.logDetector))

		for service, ld := range sd.logDetector {
			var selection []string
			prompt := &survey.MultiSelect{
				Message:  fmt.Sprintf("Logs files found for service '%s'", service),
				Options:  ld.ExistingFiles,
				PageSize: 10,
				Default:  ld.ExistingFiles,
			}
			err := survey.AskOne(prompt, &selection, survey.WithPageSize(10))
			if err == terminal.InterruptErr {
				log.Printf("returning to main menu")
				return nil
			} else if err != nil {
				return err
			}
			ld.ExistingFiles = selection
		}

		for {
			addCustomLogs := ""

			prompt := &survey.Input{
				Message: "Do you want to add other logs file or folder (glob is supported) ? (Y/n)",
			}
			err := survey.AskOne(prompt, &addCustomLogs)
			if err == terminal.InterruptErr {
				break
			} else if err != nil {
				return err
			}
			if strings.ToUpper(addCustomLogs) == "N" || strings.ToUpper(addCustomLogs) == "NO" {
				break
			}
			logFile := ""
			logType := ""

			prompt = &survey.Input{
				Message: "Log file type : ",
			}
			err = survey.AskOne(prompt, &logType)
			if err == terminal.InterruptErr {
				break
			} else if err != nil {
				return err
			}

			multiLinePrompt := &survey.Multiline{
				Message: "Path to your logs file (one by line) :",
			}
			err = survey.AskOne(multiLinePrompt, &logFile)
			if err == terminal.InterruptErr {
				break
			} else if err != nil {
				return err
			}
			logFiles := strings.Fields(logFile)

			sd.NewLog(logFiles, logType)
		}

		err = sd.GenerateConfig()
		if err != nil {
			return err
		}

		if err := cwhub.UpdateHubIdx(); err != nil {
			return err
		}

		if err := cwhub.GetHubIdx(); err != nil {
			return err
		}

		var defaultCollections []string
		for _, collection := range sd.collectionsDependency {
			defaultCollections = append(defaultCollections, collection...)
		}

		var allCollection []string
		for collectionName := range cwhub.HubIdx["collections"] {
			allCollection = append(allCollection, collectionName)
		}

		var selection []string
		prompt := &survey.MultiSelect{
			Message:  fmt.Sprintf("Install collections from CrowdSec Hub"),
			Options:  allCollection,
			PageSize: 10,
			Default:  defaultCollections,
		}
		err = survey.AskOne(prompt, &selection, survey.WithPageSize(10))
		if err == terminal.InterruptErr {
			log.Printf("returning to main menu")
			return nil
		} else if err != nil {
			return err
		}
		for _, collectionToInstall := range selection {
			for collectionName, Item := range cwhub.HubIdx["collections"] {
				if collectionName == collectionToInstall {
					log.Printf("installing collection '%s'", collectionName)
					if Item, err = cwhub.DownloadLatest(Item, cwhub.Hubdir, true, crowdsecConfig["data_dir"]); err != nil {
						return err
					}
					if _, err := cwhub.EnableItem(Item, cwhub.Installdir, crowdsecConfig["data_dir"]); err != nil {
						return err
					}
					break
				}
			}
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
