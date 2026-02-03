package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Path to the file containing the version variable
const versionFile = "internal/cli/root.go"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./scripts/release <major|minor|patch>")
		os.Exit(1)
	}
	bumpType := os.Args[1]

	// 1. Read current version
	content, err := os.ReadFile(versionFile)
	if err != nil {
		fatal("Could not read version file: %v", err)
	}
	fileContent := string(content)

	// Regex to find `Version = "x.y.z"`
	re := regexp.MustCompile(`Version\s*=\s*"(\d+)\.(\d+)\.(\d+)"`)
	matches := re.FindStringSubmatch(fileContent)
	if len(matches) < 4 {
		fatal("Could not find version string in %s", versionFile)
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])
	currentVersion := fmt.Sprintf("%d.%d.%d", major, minor, patch)

	// 2. Calculate new version
	switch bumpType {
	case "major":
		major++
		minor = 0
		patch = 0
	case "minor":
		minor++
		patch = 0
	case "patch":
		patch++
	default:
		fatal("Invalid bump type '%s'. Use major, minor, or patch.", bumpType)
	}

	newVersion := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	fmt.Printf("Bumping version: %s -> %s\n", currentVersion, newVersion)

	// 3. Update file
	newContent := strings.Replace(fileContent, fmt.Sprintf(`Version   = "%s"`, currentVersion), fmt.Sprintf(`Version   = "%s"`, newVersion), 1)
	if err := os.WriteFile(versionFile, []byte(newContent), 0o644); err != nil {
		fatal("Could not write version file: %v", err)
	}

	// 4. Git operations
	tag := "v" + newVersion
	commitMsg := fmt.Sprintf("chore: release %s", tag)

	fmt.Println("\nExecuting Git commands...")

	run("git", "add", versionFile)
	run("git", "commit", "-m", commitMsg)
	run("git", "tag", tag)

	fmt.Printf("\n✓ Successfully bumped to %s and created tag.\n", tag)
	fmt.Println("To push changes and trigger release, run:")
	fmt.Printf("  git push origin main && git push origin %s\n", tag)
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("> %s %s\n", name, strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		fatal("Command failed: %v", err)
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Printf("Error: "+format+"\n", args...)
	os.Exit(1)
}
