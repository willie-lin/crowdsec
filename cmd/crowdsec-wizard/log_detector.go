package main

import (
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

type logDetector struct {
	Name          string
	Files         []string
	Detected      bool
	ExistingFiles []string
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
