package dashboard

import (
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/dashboard/container"
	"github.com/crowdsecurity/crowdsec/pkg/dashboard/grafana"
	"github.com/crowdsecurity/crowdsec/pkg/dashboard/metabase"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type DashboardI interface {
	Setup(*csconfig.DatabaseCfg, string, string, string, string, container.Options) (*Dashboard, error)
	Start() error
	Stop() error
	Remove() error
}

type Config struct {
	Type                  string                // metabase|grafana
	Database              *csconfig.DatabaseCfg `yaml:"database"`
	ListenAddr            string                `yaml:"listen_addr"`
	ListenPort            int                   `yaml:"listen_port"`
	ListenURL             string                `yaml:"listen_url"`
	Username              string                `yaml:"username"`
	Password              string                `yaml:"password"`
	Options               *Options              `yaml:"options"`
	DashboardConfigFolder string                `yaml:"dashboard_config_folder"`
}

type Options struct {
	ShareFolder string
	DockerIPGW  string
}

type Dashboard struct {
	Config    *Config
	Dash      *DashboardI
	Container container.Container
	Options   *Options
	Metabase  *metabase.Metabase
	Grafana   *grafana.Grafana
}

func NewDashboard() *Dashboard {
	dashboard := &Dashboard{}

	return dashboard
}

func (d *Dashboard) Init(config *Config) error {
	switch config.Database.Type {
	case "sqlite":
		d.Metabase = metabase.NewMetabase()
		d.Config = config
		d.Config.Type = "metabase"
		if err := d.Metabase.Init(&metabase.Config{
			Database:     config.Database,
			ListenAddr:   config.ListenAddr,
			ListenPort:   config.ListenPort,
			Username:     config.Username,
			Password:     config.Password,
			SharedFolder: config.Options.ShareFolder,
			ListenURL:    config.ListenURL,
		}); err != nil {
			return err
		}
	case "mysql", "postgresql", "postgres":

	}
	return nil
}

func (d *Dashboard) Setup() error {
	switch d.Config.Type {
	case "metabase":
		if err := d.Metabase.Setup(); err != nil {
			return err
		}
		if err := d.Metabase.DumpConfig(filepath.Join(d.Config.DashboardConfigFolder, "metabase.yaml")); err != nil {
			return err
		}
	case "grafana":
	}
	return nil
}
