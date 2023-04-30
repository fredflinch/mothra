package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/hillu/go-yara/v4"
)

type config struct {
	filemask    string
	scantimeout time.Duration
	server_addr string
	server_port int
	mode        string
}

type filematch struct {
	rule     yara.MatchRule
	filename string
}

type procmatch struct {
	rule yara.MatchRule
	pid  int
}

func procscan(pid int, rules *yara.Rules, conf config) (matches yara.MatchRules) {
	rules.ScanProc(pid, 1, conf.scantimeout, &matches)
	return
}

func filescan(fname string, rules *yara.Rules, conf config) (matches yara.MatchRules) {
	rules.ScanFile(fname, 1, conf.scantimeout, &matches)
	return
}

func compilerules(rules string) (compRules *yara.Rules) {
	compiler, _ := yara.NewCompiler()
	fstat, _ := os.Stat(rules)

	if fstat.IsDir() {
		content, _ := ioutil.ReadDir(rules)
		for _, file := range content {
			r, _ := regexp.Compile("\\S+\\.yar(|a)")
			if r.MatchString(file.Name()) {
				frules, _ := os.Open(rules + file.Name())
				compiler.AddFile(frules, "")
				frules.Close()
			}
		}
		var err error
		compRules, err = compiler.GetRules()
		if err != nil {
			fmt.Println("[!] Error Compiling Rules [!]")
		}

		return
	}

	frules, _ := os.Open(rules)
	compiler.AddFile(frules, "")
	frules.Close()
	compRules, err := compiler.GetRules()

	if err != nil {
		fmt.Println("[!] Error Compiling Rules [!]")
	}

	return
}

// function currently low function -- to be utilised to implment config parsing
func parseConfig() (configuration config) {
	configuration.filemask = ".+"
	configuration.scantimeout = time.Duration(30)
	configuration.server_addr = "127.0.0.1"
	configuration.server_port = 80
	configuration.mode = "basic"
	return
}

func main() {
	pid := flag.Int("pid", -1, "Process ID of proc memory to scan -- likely the webserver process")
	rulePath := flag.String("rules", "", "Path to .yar rule files - supports indervidual files or directories")
	fname := flag.String("file", "", "file to scan with rules")
	// configf := flag.String("config", "", "Config file location")
	flag.Parse()

	var fhits []filematch
	var phits []procmatch

	conf := parseConfig()
	rules := compilerules(*rulePath)

	if *fname != "" {
		r, _ := os.Stat(*fname)
		if r.IsDir() {
			fmask, _ := regexp.Compile(conf.filemask)
			filepath.Walk(*fname,
				func(path string, _ os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if fmask.MatchString(path) {
						v := filescan(path, rules, conf)
						for _, m := range v {
							fhits = append(fhits, filematch{m, path})
						}
					}
					return nil
				})
		} else {
			v := filescan(*fname, rules, conf)
			for _, m := range v {
				fhits = append(fhits, filematch{m, *fname})
			}
		}

	}

	if *pid != -1 {
		v := procscan(*pid, rules, conf)
		for _, m := range v {
			phits = append(phits, procmatch{m, *pid})
		}
	}

	// Unimportant - just testing
	if len(fhits) > 0 {
		fmt.Println(fhits[0])
	}
	if len(phits) > 0 {
		fmt.Println(phits[0])
	}

}
