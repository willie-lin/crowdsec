package main

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/crowdsecurity/crowdwatch/pkg/acquisition"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type serviceDetector struct {
	logDetector map[string]*logDetector
}

type serviceFactory struct {
	LogsFile      []string `json:"logs_file"`
	HubCollection []string `json:"collections"`
}

var acquisFilePath = "./acquis.yaml"

func NewServices() (*serviceDetector, error) {
	sd := &serviceDetector{}
	sd.logDetector = make(map[string]*logDetector)

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
	}

	return sd, nil
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
	f, err := os.OpenFile(acquisFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
