package main

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"path/filepath"

	"github.com/crowdsecurity/crowdwatch/pkg/acquisition"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type logDetector struct {
	Name          string
	Files         []string
	Detected      bool
	ExistingFiles []string
}

type serviceDetector struct {
	LD map[string]*logDetector
}

func NewServices() (*serviceDetector, error) {
	sd := &serviceDetector{}
	sd.LD = make(map[string]*logDetector)

	var unmarshallData map[string][]string

	file, err := ioutil.ReadFile("./services.json")
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = json.Unmarshal([]byte(file), &unmarshallData)
	if err != nil {
		log.Fatalf(err.Error())
	}

	var ld *logDetector
	for service, logsFile := range unmarshallData {
		ld = &logDetector{
			Name:  service,
			Files: logsFile,
		}
		sd.LD[service] = ld
	}

	return sd, nil
}

func (sd *serviceDetector) Detect() error {
	for _, ld := range sd.LD {
		err := ld.Detect()
		if err != nil {
			return err
		}
	}

	return nil
}

func (sd *serviceDetector) GenerateConfig() error {
	f, err := os.OpenFile("./acquis.yaml", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	yamlEncoder := yaml.NewEncoder(f)

	for service, ld := range sd.LD {
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
	return nil
}

func (ld *logDetector) Detect() error {

	for _, filePattern := range ld.Files {
		matchedFiles, err := filepath.Glob(filePattern)
		log.Debugf("pattern '%s' matched : '%v'", filePattern, matchedFiles)
		if err != nil {
			return err
		}
		if len(matchedFiles) > 0 {
			ld.Detected = true
			ld.ExistingFiles = append(ld.ExistingFiles, matchedFiles...)
		}
	}
	return nil
}
