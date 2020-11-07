package dashboard

import (
	"github.com/crowdsecurity/crowdsec/pkg/dashboard/container"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type DashboardI interface {
	Setup(*csconfig.DatabaseCfg, string, string, string, string, container.Options) (*Dashboard, error)
	Start() error
	Stop() error
	Remove() error
}

type Config struct {
	Type      string // metabase|grafana
	Dash      *DashboardI
	Container container.Container
}

type Dashboard struct {
	Config *Config
	Dash   *DashboardI
}
