/*
Copyright © 2024 Ashot Karapetian

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"pScan/scan"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	ErrInvalidTCPPortValue = errors.New("invalid TCP port value")
	ErrInvalidPortRange    = errors.New("invalid range for ports")
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a port scan on the hosts",
	RunE: func(cmd *cobra.Command, args []string) error {
		hostsFile := viper.GetString("hosts-file")

		timeout, err := cmd.Flags().GetInt("timeout")
		if err != nil {
			return err
		}

		strPorts, err := cmd.Flags().GetString("ports")
		if err != nil {
			return err
		}

		ports, err := parsePorts(strPorts)
		if err != nil {
			return fmt.Errorf("invalid port value: %q", err)
		}

		return scanAction(os.Stdout, hostsFile, ports, timeout)
	},
}

func scanAction(out io.Writer, hostsFile string, ports []int, timeout int) error {
	hl := &scan.HostList{}

	if err := hl.Load(hostsFile); err != nil {
		return err
	}

	results := scan.Run(hl, ports, timeout)

	return printResults(out, results)
}

func printResults(out io.Writer, results []scan.Results) error {
	message := ""

	for _, r := range results {
		message += fmt.Sprintf("%s:", r.Host)

		if r.NotFound {
			message += fmt.Sprintf(" Host not found\n\n")
			continue
		}

		message += fmt.Sprintln()

		for _, p := range r.PortStates {
			message += fmt.Sprintf("\t%d: %s\n", p.Port, p.Open)
		}

		message += fmt.Sprintln()
	}

	_, err := fmt.Fprint(out, message)
	return err
}

// parsePorts parses TCP ports string into ports slice
func parsePorts(strPorts string) ([]int, error) {
	strPorts = strings.Replace(strPorts, ",", " ", -1)

	ports, err := extractNumbers(strPorts)
	if err != nil {
		return nil, err
	}

	return ports, nil
}

// extractNumbers extracts port numbers from string
func extractNumbers(strPorts string) ([]int, error) {
	ports := make([]int, 0)

	strPorts = strings.Replace(strPorts, ",", " ", -1)

	re := regexp.MustCompile("\\s+")
	strPorts = re.ReplaceAllString(strPorts, " ")

	slicePorts := strings.Split(strPorts, " ")

	for _, p := range slicePorts {
		if strings.Contains(p, "-") {
			borders := strings.Split(p, "-")
			if len(borders) != 2 {
				return nil, ErrInvalidPortRange
			}

			start, err := strconv.Atoi(borders[0])
			if err != nil {
				return nil, ErrInvalidTCPPortValue
			}
			end, err := strconv.Atoi(borders[1])
			if err != nil {
				return nil, ErrInvalidTCPPortValue
			}

			if start > end {
				return nil, ErrInvalidPortRange
			}

			for i := start; i <= end; i++ {
				if isValid(i) {
					if !exist(i, ports) {
						ports = append(ports, i)
					}
				} else {
					return nil, ErrInvalidTCPPortValue
				}
			}
			continue
		}

		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, ErrInvalidTCPPortValue
		}

		if isValid(port) {
			if !exist(port, ports) {
				ports = append(ports, port)
			}
		} else {
			return nil, ErrInvalidTCPPortValue
		}
	}

	return ports, nil
}

// exist checks whether port exists in slice or not
func exist(port int, pSlice []int) bool {
	for _, p := range pSlice {
		if p == port {
			return true
		}
	}

	return false
}

// isValid validates port numbers within the proper range for TCP range
func isValid(port int) bool {
	return port >= 1 && port <= 65535
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringP("ports", "p", "22 80-82 443", "ports or ports ranges to scan (separated with commas or spaces)")
	scanCmd.Flags().IntP("timeout", "t", 1, "scan duration")
}
