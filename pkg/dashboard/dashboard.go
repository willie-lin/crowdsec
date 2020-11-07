package dashboard

import (
	"container"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type DashboardI interface {
	Setup(*csconfig.DatabaseCfg, string, string, string, string, container.Options) (*Dashboard, error)
	Start() error
	Stop() error
	Remove() error
}

type Dashboard struct {
	Config *Config
	Dash   *DashboardI
}
