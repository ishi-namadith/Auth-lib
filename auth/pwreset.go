package authentication

import (
    "bytes"
    "crypto/tls"
    "fmt"
    "html/template"
    "net/smtp"
)

type SMTPEmailService struct {
    config EmailConfig
}

func NewEmailService(config EmailConfig) EmailService {
    return &SMTPEmailService{
        config: config,
    }
}

func (s *SMTPEmailService) SendOTP(to, otp string) error {
    // HTML template for the email
    htmlTemplate := `
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Your OTP Code</h2>
        <p>Your one-time password is:</p>
        <h1 style="color: #4CAF50; font-size: 32px; letter-spacing: 2px;">{{.OTP}}</h1>
        <p>This code will expire in 15 minutes.</p>
        <p>If you didn't request this code, please ignore this email.</p>
    </body>
    </html>
    `

    // Parse template
    tmpl, err := template.New("otpEmail").Parse(htmlTemplate)
    if err != nil {
        return fmt.Errorf("failed to parse email template: %w", err)
    }

    // Execute template with OTP
    var body bytes.Buffer
    if err := tmpl.Execute(&body, struct{ OTP string }{OTP: otp}); err != nil {
        return fmt.Errorf("failed to execute email template: %w", err)
    }

    // Setup email headers
    headers := make(map[string]string)
    headers["From"] = s.config.From
    headers["To"] = to
    headers["Subject"] = "Your OTP Code"
    headers["MIME-Version"] = "1.0"
    headers["Content-Type"] = "text/html; charset=UTF-8"

    // Build email message
    var message bytes.Buffer
    for k, v := range headers {
        message.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
    }
    message.WriteString("\r\n")
    message.Write(body.Bytes())

    // Setup authentication
    auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)

    // Setup TLS config
    tlsConfig := &tls.Config{
        ServerName: s.config.Host,
        MinVersion: tls.VersionTLS12,
    }

    // Connect to SMTP server
    addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
    
    if s.config.UseTLS {
        err = sendMailTLS(addr, auth, s.config.From, []string{to}, message.Bytes(), tlsConfig)
    } else {
        err = smtp.SendMail(addr, auth, s.config.From, []string{to}, message.Bytes())
    }

    if err != nil {
        return fmt.Errorf("failed to send email: %w", err)
    }

    return nil
}

// Helper function for TLS emails
func sendMailTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte, tlsConfig *tls.Config) error {
    conn, err := tls.Dial("tcp", addr, tlsConfig)
    if err != nil {
        return err
    }
    defer conn.Close()

    client, err := smtp.NewClient(conn, tlsConfig.ServerName)
    if err != nil {
        return err
    }
    defer client.Close()

    if err = client.Auth(auth); err != nil {
        return err
    }

    if err = client.Mail(from); err != nil {
        return err
    }

    for _, addr := range to {
        if err = client.Rcpt(addr); err != nil {
            return err
        }
    }

    w, err := client.Data()
    if err != nil {
        return err
    }

    _, err = w.Write(msg)
    if err != nil {
        return err
    }

    err = w.Close()
    if err != nil {
        return err
    }

    return client.Quit()
}