package orchestrator

import (
	"path/filepath"
	"strings"
)

// Profile defines the settings for a specific analysis file type.
type Profile struct {
	Name        string
	LaunchPath  string
	LaunchArgs  []string
	TimeoutSec  int
	EnableHooks bool
}

// GetProfileForFile selects the appropriate policy depending on magic byte/extensions.
func GetProfileForFile(filePath string) Profile {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	switch ext {
	case ".dll":
		return Profile{
			Name:        "DLL Loader Profile",
			LaunchPath:  "rundll32.exe",
			LaunchArgs:  []string{filePath, ",#1"}, // Invoke ordinal 1 or default DllRegisterServer
			TimeoutSec:  60,
			EnableHooks: true,
		}
	case ".ps1":
		return Profile{
			Name:        "PowerShell Script Profile",
			LaunchPath:  "powershell.exe",
			LaunchArgs:  []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filePath},
			TimeoutSec:  90,
			EnableHooks: true,
		}
	case ".bat", ".cmd":
		return Profile{
			Name:        "Batch Script Profile",
			LaunchPath:  "cmd.exe",
			LaunchArgs:  []string{"/c", filePath},
			TimeoutSec:  60,
			EnableHooks: true,
		}
	default:
		// Default binary profile (EXE/ELF)
		return Profile{
			Name:        "Standard Executable Profile",
			LaunchPath:  filePath,
			LaunchArgs:  []string{},
			TimeoutSec:  120,
			EnableHooks: true,
		}
	}
}
