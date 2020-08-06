package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type serviceDetector struct {
	logDetector           map[string]*logDetector
	collectionsDependency map[string][]string
}

type serviceFactory struct {
	LogsFile      []string `json:"logs_file"`
	HubCollection []string `json:"collections"`
}

var acquisFilename = "acquis.yaml"
var acquisFilePath = fmt.Sprintf("./%s", acquisFilename)

func NewServices() (*serviceDetector, error) {
	sd := &serviceDetector{}
	sd.logDetector = make(map[string]*logDetector)
	sd.collectionsDependency = make(map[string][]string)

	var unmarshallData map[string]serviceFactory

	file, err := ioutil.ReadFile("./services.json")
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = json.Unmarshal([]byte(file), &unmarshallData)
	if err != nil {
		log.Fatalf(err.Error())
	}

	var ld *logDetector
	for service, info := range unmarshallData {
		ld = &logDetector{
			Name:  service,
			Files: info.LogsFile,
		}
		sd.logDetector[service] = ld
		sd.collectionsDependency[service] = info.HubCollection
	}

	return sd, nil
}

func (sd *serviceDetector) AddLogsFile(files []string, fileType string) error {

	if _, ok := sd.logDetector[fileType]; ok {
		sd.logDetector[fileType].ExistingFiles = append(sd.logDetector[fileType].ExistingFiles, files...)
	} else {
		ld := &logDetector{
			Name:          fileType,
			ExistingFiles: files,
		}
		sd.logDetector[fileType] = ld
	}

	return nil
}

func (sd *serviceDetector) Detect() error {
	for _, ld := range sd.logDetector {
		err := ld.Detect()
		if err != nil {
			return err
		}
	}

	return nil
}

func (sd *serviceDetector) GenerateConfig() error {
	f, err := os.OpenFile(fmt.Sprintf("./%s", acquisFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	yamlEncoder := yaml.NewEncoder(f)

	for service, ld := range sd.logDetector {
		acquis := &acquisition.FileCtx{
			Mode:   "tail",
			Labels: make(map[string]string),
		}

		acquis.Labels["type"] = service

		switch len(ld.ExistingFiles) {
		case 0:
			return nil
		case 1:
			acquis.Filename = ld.ExistingFiles[0]
		default:
			acquis.Filenames = append(acquis.Filenames, ld.ExistingFiles...)
		}

		err = yamlEncoder.Encode(acquis)
		if err != nil {
			return err
		}

	}
	log.Printf("'%s' file generated", acquisFilePath)
	return nil
}

func (sd *serviceDetector) Run() error {
	err := sd.Detect()
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

		sd.AddLogsFile(logFiles, logType)
	}

	err = sd.GenerateConfig()
	if err != nil {
		return err
	}
	return nil
}

func (sd *serviceDetector) installDependency() error {
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
		if strInSlice(collectionName, defaultCollections) {
			allCollection = append([]string{collectionName}, allCollection...) // If the collection is in default, we want to add it at the begining
		} else {
			allCollection = append(allCollection, collectionName)
		}
	}

	var selection []string
	prompt := &survey.MultiSelect{
		Message:  fmt.Sprintf("Install collections from CrowdSec Hub"),
		Options:  allCollection,
		PageSize: 10,
		Default:  defaultCollections,
	}
	err := survey.AskOne(prompt, &selection, survey.WithPageSize(10))
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
	return nil
}
