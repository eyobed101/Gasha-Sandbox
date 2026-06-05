//go:build ignore

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

func main() {
	fmt.Println("[*] Starting benign behavior simulator...")
	time.Sleep(1 * time.Second)

	// 1. Simulate File-Based Persistence Write
	// We use a path containing "\startup\" to trigger the rule condition
	tempDir := os.Getenv("TEMP")
	startupSimDir := filepath.Join(tempDir, "startup")
	_ = os.MkdirAll(startupSimDir, 0755)
	
	testFilePath := filepath.Join(startupSimDir, "lemas_benign_test.txt")
	fmt.Printf("[*] Writing test persistence file: %s\n", testFilePath)
	err := os.WriteFile(testFilePath, []byte("benign test payload"), 0644)
	if err != nil {
		fmt.Printf("[-] Failed to write test file: %v\n", err)
	}

	// 2. Simulate Registry-Based Persistence Set
	// We write to HKCU\Software\LEMAS_Test_Run (contains "\run" or "run" pattern)
	fmt.Println("[*] Setting test registry run key...")
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\LEMAS_Test_Run`, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("[-] Failed to create registry key: %v\n", err)
	} else {
		err = k.SetStringValue("TestKey", "C:\\Windows\\System32\\cmd.exe")
		if err != nil {
			fmt.Printf("[-] Failed to set registry value: %v\n", err)
		}
		k.Close()
	}

	// 3. Spawn a child process to trigger Process Create ETW event
	fmt.Println("[*] Spawning child process...")
	cmd := exec.Command("cmd.exe", "/c", "echo", "LEMAS telemetry test")
	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Failed to spawn child process: %v\n", err)
	}

	// 4. Initiate a benign TCP outbound connection to trigger Network ETW event
	fmt.Println("[*] Initiating connection to example.com:80...")
	conn, err := net.DialTimeout("tcp", "example.com:80", 5*time.Second)
	if err != nil {
		fmt.Printf("[-] Failed network connection: %v\n", err)
	} else {
		fmt.Println("[+] Connection established successfully.")
		conn.Close()
	}

	// Clean up registry test key
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\LEMAS_Test_Run`)
	// Clean up file
	_ = os.Remove(testFilePath)
	_ = os.Remove(startupSimDir)

	fmt.Println("[+] Done. Telemetry sequence completed.")
}
