package main

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
)

var (
	actionPriority = map[int]string{
		0: "install_crowdsec",
		1: "upgrade_crowdsec",
		2: "detect_and_write_logs",
		3: "install_blockers",
		4: "uninstall_crowdsec",
	}

	menuAction = map[string]string{
		"install_crowdsec":      "\n  (1) Install CrowdSec\n",
		"upgrade_crowdsec":      "(2) Upgrade CrowdSec\n",
		"detect_and_write_logs": "(3) Detect Logs and generate acquisition configuration\n",
		"install_blockers":      "(4) Install blocker(s)\n",
		"uninstall_crowdsec":    "(5) Uninstall CrowdSec\n",
	}

	crowdsecConfig = map[string]string{
		"data_dir":  "/var/lib/crowdsec/data",
		"cscli_dir": "/etc/crowdsec/config/cscli",
	}
)

func main() {

	sd, err := NewServices()
	if err != nil {
		log.Fatalf(err.Error())
	}
	err = sd.Detect()
	if err != nil {
		log.Fatalf(err.Error())
	}

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

	menuResp := struct {
		Action string `survey:"color"`
	}{}

	err = survey.Ask(qs, &menuResp)
	if err != nil {
		log.Fatalf("here : %s", err.Error())
	}

	reverseBack := make(map[string]string, len(menuAction))
	for id, action := range menuAction {
		reverseBack[action] = id
	}

	switch action := reverseBack[menuResp.Action]; action {
	case "install_crowdsec":
	case "upgrade_crowdsec":
	case "detect_and_write_logs":
		log.Printf("detected %d services", len(sd.logDetector))

		for service, ld := range sd.logDetector {
			var selection []string
			prompt := &survey.MultiSelect{
				Message:  fmt.Sprintf("Logs files found for service %s", service),
				Options:  ld.ExistingFiles,
				PageSize: 10,
				Default:  ld.ExistingFiles,
			}
			survey.AskOne(prompt, &selection, survey.WithPageSize(10))
			ld.ExistingFiles = selection
		}

		err = sd.GenerateConfig()
		if err != nil {
			log.Fatalf(err.Error())
		}

		if err := cwhub.UpdateHubIdx(); err != nil {
			log.Fatalf(err.Error())
		}

		if err := cwhub.GetHubIdx(); err != nil {
			log.Fatalf(err.Error())
		}

		var defaultCollections []string

		for _, collection := range sd.collectionsDependency {
			defaultCollections = append(defaultCollections, collection...)
		}

		var allCollection []string
		for collectionName, _ := range cwhub.HubIdx["collections"] {
			allCollection = append(allCollection, collectionName)
		}

		var selection []string
		prompt := &survey.MultiSelect{
			Message:  fmt.Sprintf("Install collections from CrowdSec Hub"),
			Options:  allCollection,
			PageSize: 10,
			Default:  defaultCollections,
		}
		survey.AskOne(prompt, &selection, survey.WithPageSize(10))

		for _, collectionToInstall := range selection {
			for collectionName, Item := range cwhub.HubIdx["collections"] {
				if collectionName == collectionToInstall {
					log.Printf("installing collection '%s'", collectionName)
					if _, err := cwhub.DownloadLatest(Item, crowdsecConfig["cscli_dir"], true, crowdsecConfig["data_dir"]); err != nil {
						log.Fatalf(err.Error())
					}
					break
				}
			}
		}

	case "install_blockers":
	case "uninstall_crowdsec":
	default:
		log.Fatalf("unknown action : '%s'", action)
	}

}
