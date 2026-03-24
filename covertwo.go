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

// Configuration via Environment Variables with defaults
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var (
	s3Bucket       = getEnv("COVERTWO_BUCKET", "your-public-bucket")
	s3Key          = getEnv("COVERTWO_KEY", "blocklist.txt")
	awsRegion      = getEnv("AWS_REGION", "us-east-1")
	pfAnchor       = getEnv("COVERTWO_PF_ANCHOR", "com.user.covertwo")
	dbPath         = getEnv("COVERTWO_DB_PATH", "/usr/local/var/db/covertwo")
	syncIntervalSeconds = 60 
)

func main() {
	// 1. Ensure directory exists
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		logWithTimestamp(fmt.Sprintf("Init Error: %v", err))
		os.Exit(1)
	}

	// 2. PF Check
	if err := ensurePFEnabled(); err != nil {
		logWithTimestamp(fmt.Sprintf("PF Error: %v", err))
		log.Println("Note: This service requires sudo/root permissions to manage PF.")
		os.Exit(1)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			logWithTimestamp("Syncing blocklist...")
			if err := syncBlocklist(); err != nil {
				logWithTimestamp(fmt.Sprintf("Sync Error: %v", err))
			}
			time.Sleep(time.Duration(syncIntervalSeconds) * time.Second)
		}
	}()

	<-stop
	logWithTimestamp("Shutting down gracefully.")
}

func ensurePFEnabled() error {
	cmd := exec.Command("pfctl", "-e")
	output, _ := cmd.CombinedOutput() // -e returns error if already enabled, so we check status instead
	
	statusCmd := exec.Command("pfctl", "-s", "info")
	statusOut, _ := statusCmd.Output()
	if !strings.Contains(string(statusOut), "Status: Enabled") {
		return fmt.Errorf("could not enable PF. Output: %s", string(output))
	}
	return nil
}

func syncBlocklist() error {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(awsRegion)})
	if err != nil {
		return err
	}

	svc := s3.New(sess)
	result, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		return err
	}
	defer result.Body.Close()

	content, _ := io.ReadAll(result.Body)
	processed := processBlocklist(content)

	processedFile := fmt.Sprintf("%s/processed.txt", dbPath)
	oldContent, _ := os.ReadFile(processedFile)

	if string(oldContent) == string(processed) {
		return nil // No changes
	}

	os.WriteFile(processedFile, processed, 0644)
	return applyToPF(processed)
}

func processBlocklist(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	var validIPs []string
	for _, line := range lines {
		clean := strings.TrimSpace(strings.Split(line, "#")[0])
		if clean != "" && net.ParseIP(clean) != nil {
			validIPs = append(validIPs, clean)
		}
	}
	return []byte(strings.Join(validIPs, "\n"))
}

func applyToPF(blocklist []byte) error {
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-t", "blocklist", "-T", "replace", "-f", "-")
	cmd.Stdin = bytes.NewReader(blocklist)
	return cmd.Run()
}

func logWithTimestamp(msg string) {
	log.Printf("[%s] %s\n", time.Now().Format(time.RFC3339), msg)
}
