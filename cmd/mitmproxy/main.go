package main

import (
	"flag"
	"os"

	"github.com/lqqyt2423/go-mitmproxy/addon"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	addr      string
	dump      string // dump filename
	dumpLevel int    // dump level
}

func loadConfig() *Config {
	config := new(Config)

	flag.StringVar(&config.addr, "addr", ":9080", "proxy listen addr")
	flag.StringVar(&config.dump, "dump", "", "dump filename")
	flag.IntVar(&config.dumpLevel, "dump_level", 0, "dump level: 0 - header, 1 - header + body")
	flag.Parse()

	return config
}

func main() {
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(false)
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	config := loadConfig()

	opts := &proxy.Options{
		Addr:              config.addr,
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	if config.dump != "" {
		dumper := addon.NewDumper(config.dump, config.dumpLevel)
		p.AddAddon(dumper)
	}

	log.Fatal(p.Start())
}
