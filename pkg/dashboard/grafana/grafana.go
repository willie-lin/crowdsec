package grafana

import (
	"fmt"
	"io/ioutil"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/dashboard/container"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Grafana struct {
	Container *container.Container
	Config    *Config
}

var (
	metabaseDefaultUser     = "crowdsec@crowdsec.net"
	metabaseDefaultPassword = "!!Cr0wdS3c_M3t4b4s3??"
	containerName           = "/crowdsec-grafana"
	containerImage          = "grafana/grafana"

	metabaseSQLiteDBURL = "https://crowdsec-statics-assets.s3-eu-west-1.amazonaws.com/grafana_dashboard.zip"
)

type Config struct {
	Database   *csconfig.DatabaseCfg `yaml:"database"`
	ListenAddr string                `yaml:"listen_addr"`
	ListenPort int                   `yaml:"listen_port"`
	ListenURL  string                `yaml:"listen_url"`
	Username   string                `yaml:"username"`
	Password   string                `yaml:"password"`
}

func NewGrafana(configPath string) (*Grafana, error) {
	g := &Grafana{}
	if err := g.LoadConfig(configPath); err != nil {
		return g, err
	}
	if err := g.Init(); err != nil {
		return g, err
	}
	return g, nil
}

func (g *Grafana) LoadConfig(configPath string) error {
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	config := &Config{}

	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		return err
	}
	if config.Username == "" {
		return fmt.Errorf("'username' not found in configuration file '%s'", configPath)
	}

	if config.Password == "" {
		return fmt.Errorf("'password' not found in configuration file '%s'", configPath)
	}

	if config.ListenURL == "" {
		return fmt.Errorf("'listen_url' not found in configuration file '%s'", configPath)
	}

	g.Config = config

	if err := g.Init(); err != nil {
		return err
	}

	return nil

}

func (g *Grafana) Init() error {
	var err error

	switch g.Config.Database.Type {
	case "mysql", "postgresql", "postgres":
	default:
		return fmt.Errorf("database '%s' not supported", g.Config.Database.Type)
	}

	options := &container.Options{
		Shares:        []*container.Share{},
		Env:           []string{},
		ListenAddress: g.Config.ListenAddr,
		ListenPort:    g.Config.ListenPort,
		BindPort:      3000,
	}

	g.Container, err = container.NewContainer(containerName, containerImage, options)
	if err != nil {
		return errors.Wrap(err, "container init")
	}
	return nil
}
