package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type WhatsAppService struct {
	apiURL   string
	deviceID string
	username string
	password string
}

func NewWhatsAppService() *WhatsAppService {
	return &WhatsAppService{
		apiURL:   os.Getenv("WHATSAPP_API_URL"),
		deviceID: os.Getenv("WHATSAPP_DEVICE_ID"),
		username: os.Getenv("WHATSAPP_API_USER"),
		password: os.Getenv("WHATSAPP_API_PASSWORD"),
	}
}

type whatsAppMessageRequest struct {
	Phone   string `json:"phone"`
	Message string `json:"message"`
}

type whatsAppResponse struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// SendMessage sends a WhatsApp text message to the specified phone number.
// Phone should be in format: 628xxxxxxxxxx (with country code, no + or spaces)
func (s *WhatsAppService) SendMessage(phone, message string) error {
	if s.apiURL == "" {
		return fmt.Errorf("WHATSAPP_API_URL not configured")
	}

	// Format phone number for WhatsApp API (add @s.whatsapp.net suffix if not present)
	formattedPhone := phone
	if len(phone) > 0 && phone[len(phone)-1] != 't' { // Quick check if already has @s.whatsapp.net
		formattedPhone = phone + "@s.whatsapp.net"
	}

	payload := whatsAppMessageRequest{
		Phone:   formattedPhone,
		Message: message,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/send/message", s.apiURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Set Device ID header if configured
	if s.deviceID != "" {
		req.Header.Set("X-Device-Id", s.deviceID)
	}

	// Set Basic Auth if credentials are configured
	if s.username != "" && s.password != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp whatsAppResponse
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("WhatsApp API error (status %d): %s", resp.StatusCode, errResp.Message)
	}

	return nil
}
