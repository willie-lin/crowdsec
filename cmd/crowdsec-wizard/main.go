package main

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	log "github.com/sirupsen/logrus"
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

	log.Printf("detected %d services", len(sd.LD))

	for service, ld := range sd.LD {
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

}
