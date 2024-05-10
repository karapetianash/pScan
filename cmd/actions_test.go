package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"pScan/scan"
)

func setup(t *testing.T, hosts []string, initList bool) (string, func()) {
	// Create temp file
	tf, err := os.CreateTemp("", "pScan")
	if err != nil {
		t.Fatal(err)
	}
	tf.Close()

	// Initialize list if needed
	if initList {
		hl := &scan.HostList{}

		for _, h := range hosts {
			hl.Add(h)
		}

		if err = hl.Save(tf.Name()); err != nil {
			t.Fatal(err)
		}
	}

	// Return temp file name and cleanup function
	return tf.Name(), func() {
		os.Remove(tf.Name())
	}
}

func TestHostActions(t *testing.T) {
	hosts := []string{
		"host1",
		"host2",
		"host3",
	}

	// Test cases for Action test
	testCases := []struct {
		name           string
		args           []string
		expectedOut    string
		initList       bool
		actionFunction func(io.Writer, string, []string) error
	}{

		{
			name:           "AddAction",
			args:           hosts,
			expectedOut:    "Added host: host1\nAdded host: host2\nAdded host: host3\n",
			initList:       false,
			actionFunction: addAction,
		},
		{
			name:           "ListAction",
			expectedOut:    "host1\nhost2\nhost3\n",
			initList:       true,
			actionFunction: listAction,
		},
		{
			name:           "DeleteAction",
			args:           []string{"host1", "host2"},
			expectedOut:    "Deleted host: host1\nDeleted host: host2\n",
			initList:       true,
			actionFunction: deleteAction,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup Action test
			tf, cleanup := setup(t, hosts, tc.initList)
			defer cleanup()

			// Define var to capture Action output
			var out bytes.Buffer

			// Execute Action and capture output
			if err := tc.actionFunction(&out, tf, tc.args); err != nil {
				t.Fatalf("Expected no error, got %q\n", err)
			}

			// Test Action output
			if out.String() != tc.expectedOut {
				t.Errorf("Expected output %q, got %q instead\n", tc.expectedOut, out.String())
			}
		})
	}
}

func TestIntegration(t *testing.T) {
	// Define hosts for integration test
	hosts := []string{
		"host1",
		"host2",
		"host3",
	}

	// Setup integration test
	tf, cleanup := setup(t, hosts, false)
	defer cleanup()

	delHost := "host2"

	hostsEnd := []string{
		"host1",
		"host3",
	}

	// Define var to capture output
	var out bytes.Buffer

	// Define expected output for all actions
	expectedOut := ""

	for _, v := range hosts {
		expectedOut += fmt.Sprintf("Added host: %s\n", v)
	}
	expectedOut += strings.Join(hosts, "\n")
	expectedOut += fmt.Sprintln()
	expectedOut += fmt.Sprintf("Deleted host: %s\n", delHost)
	expectedOut += strings.Join(hostsEnd, "\n")
	expectedOut += fmt.Sprintln()
	for _, v := range hostsEnd {
		expectedOut += fmt.Sprintf("%s: Host not found\n", v)
		expectedOut += fmt.Sprintln()
	}

	// Add hosts to the list
	if err := addAction(&out, tf, hosts); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// List hosts
	if err := listAction(&out, tf, nil); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// Delete delHost
	if err := deleteAction(&out, tf, []string{delHost}); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// List hosts after delete
	if err := listAction(&out, tf, nil); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// Scan hosts
	if err := scanAction(&out, tf, nil, 1); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// Test integration output
	if out.String() != expectedOut {
		t.Errorf("Expected output %q, got %q\n", expectedOut, out.String())
	}
}

// Added host: host1\nAdded host: host2\nAdded host: host3\nhost1\nhost2\nhost3\nDeleted host: host2\nhost1\nhost3\nhost1: Host not found\n\nhost3: Host not found\n\n
// Added host: host1\nAdded host: host2\nAdded host: host3\nhost1\nhost2\nhost3\nDeleted host: host2\n				host1: Host not found\n\nhost3: Host not found\n\nhost1\nhost3\n

func TestScanAction(t *testing.T) {
	// Define hosts for scan test
	hosts := []string{
		"localhost",
		"unknownhostoutthere",
	}

	// Setup scan test
	tf, cleanup := setup(t, hosts, true)
	defer cleanup()

	ports := make([]int, 0)

	// Init ports, 1 open, 1 closed
	for i := 0; i < 2; i++ {
		ln, err := net.Listen("tcp", net.JoinHostPort("localhost", "0"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		_, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatal(err)
		}

		ports = append(ports, port)

		if i == 1 {
			ln.Close()
		}
	}

	// Define expected output for scan action
	expectedOut := fmt.Sprintln("localhost:")
	expectedOut += fmt.Sprintf("\t%d: open\n", ports[0])
	expectedOut += fmt.Sprintf("\t%d: closed\n", ports[1])
	expectedOut += fmt.Sprintln()
	expectedOut += fmt.Sprintln("unknownhostoutthere: Host not found")
	expectedOut += fmt.Sprintln()

	// Define var to capture scan output
	var out bytes.Buffer

	// Execute scan and capture output
	if err := scanAction(&out, tf, ports, 1); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// Test scan output
	if out.String() != expectedOut {
		t.Errorf("Expected output %q, got %q\n", expectedOut, out.String())
	}
}

func TestParsePorts(t *testing.T) {
	testCases := []struct {
		name          string
		strPorts      string
		expectedError error
		expectedValue []int
	}{
		{"ValidCommaString", "1, 5, 7-10, 15", nil, []int{1, 5, 7, 8, 9, 10, 15}},
		{"ValidSpaceString", "1 5 7-10 15", nil, []int{1, 5, 7, 8, 9, 10, 15}},
		{"ValidMixString", "1, 5 7-10, 15", nil, []int{1, 5, 7, 8, 9, 10, 15}},
		{"NoValidTCPValueString", "1, 5, 7-10, 15, 1000000", ErrInvalidTCPPortValue, nil},
		{"NoValidRangeString", "1, 5, 7-6, 15", ErrInvalidPortRange, nil},
		{"NoValidNoValueString", "some text", ErrInvalidTCPPortValue, nil},
		{"NoValidEmptyString", "", ErrInvalidTCPPortValue, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := parsePorts(tc.strPorts)

			if tc.expectedError != nil {
				if err == nil {
					t.Fatalf("Expected error, got 'nil' instead\n")
				}

				if !errors.Is(err, tc.expectedError) {
					t.Errorf("Expected error %q, got %q instead\n", tc.expectedError, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %q instead\n", err)
			}

			if !reflect.DeepEqual(res, tc.expectedValue) {
				t.Errorf("Expected ports %v, got %v instead\n", tc.expectedValue, res)
			}
		})
	}
}

func TestIsValid(t *testing.T) {
	testCases := []struct {
		name        string
		value       int
		expectedRes bool
	}{
		{"Valid", 4, true},
		{"NoValid", 0, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expectedRes != isValid(tc.value) {
				t.Errorf("Expected %t, got %t instead\n", tc.expectedRes, isValid(tc.value))
			}
		})
	}
}

func TestExist(t *testing.T) {
	testCases := []struct {
		name        string
		port        int
		pSlice      []int
		expectedRes bool
	}{
		{"Exists", 1, []int{1, 2, 3}, true},
		{"Exists", 4, []int{1, 2, 3}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := exist(tc.port, tc.pSlice)

			if tc.expectedRes != res {
				t.Errorf("Expected %t, got %t instead\n", tc.expectedRes, res)
			}
		})
	}
}
