package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

const (
	s3BucketURL        = "covertwo"                          // S3 bucket name
	s3BlocklistKey     = "blocklist.txt"                     // S3 object key
	localBlocklistPath = "/var/db/covertwo/blocklist.txt"    // Path to the local blocklist file
	processedBlocklist = "/var/db/covertwo/processed.txt"    // Path to the processed blocklist
	pfAnchorName       = "com.example.covertwo"              // Name of the PF anchor
	syncInterval       = 60 * time.Second                    // Interval for syncing the blocklist
)

func main() {
	// Ensure the local blocklist directory exists
	if err := os.MkdirAll("/var/db/covertwo", 0755); err != nil {
		logWithTimestamp(fmt.Sprintf("Error creating blocklist directory: %v", err))
		os.Exit(1)
	}

	// Ensure PF is enabled
	if err := ensurePFEnabled(); err != nil {
		logWithTimestamp(fmt.Sprintf("Error ensuring PF is enabled: %v", err))
		os.Exit(1)
	}

	// Set up signal handling for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start the sync loop
	go func() {
		for {
			logWithTimestamp("Starting blocklist sync...")

			// Sync the blocklist
			if err := syncBlocklist(); err != nil {
				logWithTimestamp(fmt.Sprintf("Error syncing blocklist: %v", err))
			} else {
				logWithTimestamp("Blocklist synced successfully.")
			}

			// Countdown to the next sync
			countdownTimer(syncInterval)
		}
	}()

	// Wait for a signal to stop
	<-stop
	logWithTimestamp("Shutting down...")
}

// ensurePFEnabled checks if PF is enabled and enables it if necessary.
func ensurePFEnabled() error {
	cmd := exec.Command("pfctl", "-s", "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error checking PF status: %v", err)
	}

	if !strings.Contains(string(output), "Status: Enabled") {
		cmd := exec.Command("pfctl", "-e")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("error enabling PF: %v, output: %s", err, string(output))
		}
		logWithTimestamp("PF enabled successfully.")
	} else {
		logWithTimestamp("PF is already enabled.")
	}

	return nil
}

// syncBlocklist downloads and processes the blocklist from S3, then applies it.
func syncBlocklist() error {
	remoteBlocklist, err := downloadBlocklist()
	if err != nil {
		return fmt.Errorf("failed to download blocklist: %v", err)
	}

	// Validate and process the blocklist
	processed, err := processBlocklist(remoteBlocklist)
	if err != nil {
		return fmt.Errorf("failed to process blocklist: %v", err)
	}

	// Check if the blocklist has changed
	localBlocklistContent, err := os.ReadFile(processedBlocklist)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read processed blocklist: %v", err)
	}

	if string(localBlocklistContent) == string(processed) {
		logWithTimestamp("No changes in blocklist detected.")
		return nil // No changes
	}

	// Save the processed blocklist
	if err := os.WriteFile(processedBlocklist, processed, 0644); err != nil {
		return fmt.Errorf("failed to write processed blocklist: %v", err)
	}

	// Apply the blocklist
	if err := applyBlocklist(processed); err != nil {
		return fmt.Errorf("failed to apply blocklist: %v", err)
	}

	return nil
}

// downloadBlocklist fetches the blocklist from the S3 bucket.
func downloadBlocklist() ([]byte, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}

	svc := s3.New(sess)
	input := &s3.GetObjectInput{
		Bucket: aws.String(s3BucketURL),
		Key:    aws.String(s3BlocklistKey),
	}

	result, err := svc.GetObject(input)
	if err != nil {
		return nil, fmt.Errorf("failed to download blocklist: %v", err)
	}
	defer result.Body.Close()

	return io.ReadAll(result.Body)
}

// processBlocklist validates and processes the blocklist content.
func processBlocklist(content []byte) ([]byte, error) {
	lines := strings.Split(string(content), "\n")
	var validIPs []string

	for _, line := range lines {
		// Remove everything after the first '#' (including the '#')
		if strings.Contains(line, "#") {
			line = strings.SplitN(line, "#", 2)[0]
		}

		// Trim whitespace and validate the IP
		ip := strings.TrimSpace(line)
		if ip == "" {
			continue
		}

		if net.ParseIP(ip) != nil {
			validIPs = append(validIPs, ip)
		} else {
			logWithTimestamp(fmt.Sprintf("Invalid IP skipped: %s", line))
		}
	}

	return []byte(strings.Join(validIPs, "\n")), nil
}

// applyBlocklist applies the processed blocklist using pfctl.
func applyBlocklist(blocklist []byte) error {
	cmd := exec.Command("pfctl", "-a", pfAnchorName, "-t", "blocklist", "-T", "replace", "-f", "-")
	cmd.Stdin = bytes.NewReader(blocklist)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to apply blocklist: %v, output: %s", err, string(output))
	}
	logWithTimestamp("Blocklist applied successfully.")
	return nil
}

// countdownTimer displays a countdown timer for the next sync.
func countdownTimer(duration time.Duration) {
	for i := int(duration.Seconds()); i > 0; i-- {
		fmt.Printf("\rNext sync in %d seconds...", i)
		time.Sleep(1 * time.Second)
	}
	fmt.Println() // Move to the next line after the countdown
}

// logWithTimestamp logs a message with a timestamp.
func logWithTimestamp(message string) {
	log.Printf("[%s] %s\n", time.Now().UTC().Format(time.RFC3339), message)
}

