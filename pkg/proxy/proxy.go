package proxy

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"go.uber.org/zap"
	"io"
	"os"
	"os/exec"
	"text/template"
)

//go:embed  tmpl/*
var tmpl embed.FS

const (
	EnvoyConfigFile = "./envoy.yaml"
	EnvoyAdminPort  = "19000"
)

type CnvrgProxy struct {
	cmd          *exec.Cmd
	config       []byte
	envoyPath    string
	controlPlane *EnvoyControlPlane
	metricsAddr  string
}

func NewDefaultCnvrgProxy(envoyPath, metricsAddr string, cp *EnvoyControlPlane) *CnvrgProxy {
	return &CnvrgProxy{
		envoyPath:    envoyPath,
		controlPlane: cp,
		metricsAddr:  metricsAddr,
	}
}

func (p *CnvrgProxy) Run() {
	go func() {
		p.renderConfigs()
		p.dumpConfigsOnDisk()
		p.startProxy()
		p.startMetrics()
	}()

}

func (p *CnvrgProxy) StopProxy() {
	zap.S().Info("shutting down proxy")
	if err := p.cmd.Process.Kill(); err != nil {
		zap.S().Error(err)
	}
	zap.S().Info("proxy process successfully terminated")
}

func (p *CnvrgProxy) startProxy() {
	p.cmd = exec.Command(p.envoyPath, []string{"-c", EnvoyConfigFile}...)
	reader, writer := io.Pipe()
	p.cmd.Stdin = os.Stdin
	p.cmd.Stdout = writer
	p.cmd.Stderr = writer

	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			msg := scanner.Text()
			fmt.Println(msg)
		}
	}()

	go func() {
		if err := p.cmd.Run(); err != nil {
			zap.S().Fatal(err)
		}
	}()
}

func (p *CnvrgProxy) dumpConfigsOnDisk() {
	if err := os.WriteFile(EnvoyConfigFile, p.config, 0644); err != nil {
		zap.S().Fatal(err)
	}
}

func (p *CnvrgProxy) renderConfigs() {
	var tpl bytes.Buffer
	f, err := tmpl.ReadFile(ConfigTemplate)
	if err != nil {
		zap.S().Fatal(err)
	}
	t, err := template.New("config").
		Option("missingkey=error").
		Parse(string(f))

	if err != nil {
		zap.S().Fatal(err)
		return
	}

	configData := map[string]interface{}{
		"NodeCluster": p.controlPlane.NodeCluster,
		"NodeId":      p.controlPlane.NodeId,
		"ClusterName": p.controlPlane.XdsClusterName,
		"Address":     p.controlPlane.Address,
		"Port":        p.controlPlane.Port,
	}

	if err := t.Execute(&tpl, configData); err != nil {
		zap.S().Fatal(err)
	}
	p.config = tpl.Bytes()
}
