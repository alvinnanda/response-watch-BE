package services

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

type EmailService struct{}

func NewEmailService() *EmailService {
	return &EmailService{}
}

func (s *EmailService) SendEmail(to []string, subject string, body string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	username := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("EMAIL_FROM")
	fromName := os.Getenv("EMAIL_FROM_NAME")

	if host == "" || username == "" || password == "" {
		return fmt.Errorf("SMTP configuration missing")
	}

	auth := smtp.PlainAuth("", username, password, host)

	// Simple HTML template wrapping
	// Professional HTML template
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1f2937; background-color: #f3f4f6; margin: 0; padding: 0; }
    .wrapper { width: 100%%; background-color: #f3f4f6; padding: 40px 0; }
    .container { background-color: #ffffff; border-radius: 12px; max-width: 600px; margin: 0 auto; padding: 40px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); }
    .header { text-align: center; margin-bottom: 32px; }
    .brand { font-size: 24px; font-weight: 800; color: #111827; text-decoration: none; letter-spacing: -0.025em; }
    .content { font-size: 16px; color: #374151; }
    .footer { text-align: center; margin-top: 40px; }
    .footer a { font-size: 12px; font-weight: bold; color: #d1d5db; letter-spacing: 0.1em; text-transform: uppercase; text-decoration: none; }
</style>
</head>
<body>
<div class="wrapper">
    <div class="container">
        <div class="content">
            %s
        </div>
        <div class="footer">
            <a href="https://responsewatch.com">ResponseWatch</a>
        </div>
    </div>
</div>
</body>
</html>
`, body)

	// Construct message
	toHeader := strings.Join(to, ",")
	msg := []byte(fmt.Sprintf("To: %s\r\n"+
		"From: \"%s\" <%s>\r\n"+
		"Subject: %s\r\n"+
		"MIME-version: 1.0;\r\n"+
		"Content-Type: text/html; charset=\"UTF-8\";\r\n"+
		"\r\n"+
		"%s", toHeader, fromName, from, subject, htmlBody))

	addr := fmt.Sprintf("%s:%s", host, port)

	err := smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}
