package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// Scanner wraps gitleaks detector with logging.
type Scanner struct {
	detector *detect.Detector
	log      *slog.Logger
}

// ScanResult contains the findings from a scan.
type ScanResult struct {
	Secrets []string
}

// NewScanner creates a Scanner with the given config path.
// If configPath is empty, uses the default gitleaks config.
func NewScanner(configPath string, logger *slog.Logger) (*Scanner, error) {
	log := logger.With("component", "scanner")

	var detector *detect.Detector
	var err error

	if configPath != "" {
		cfg, err := loadGitleaksConfig(configPath)
		if err != nil {
			return nil, fmt.Errorf("load config from %s: %w", configPath, err)
		}
		log.Info("loaded custom gitleaks config", "path", configPath, "rules", len(cfg.Rules))
		detector = detect.NewDetector(cfg)
	} else {
		detector, err = detect.NewDetectorDefaultConfig()
		if err != nil {
			return nil, fmt.Errorf("create default gitleaks detector: %w", err)
		}
		log.Info("using default gitleaks config")
	}

	return &Scanner{detector: detector, log: log}, nil
}

func loadGitleaksConfig(configPath string) (config.Config, error) {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("toml")

	if err := v.ReadInConfig(); err != nil {
		return config.Config{}, fmt.Errorf("read config file: %w", err)
	}

	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return config.Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	cfg, err := vc.Translate()
	if err != nil {
		return config.Config{}, fmt.Errorf("translate config: %w", err)
	}

	return cfg, nil
}

// scans text for API key leaks and returns the result
func (s *Scanner) Scan(text string) ScanResult {
	s.log.Debug("scanning text", "length", len(text))

	fragment := detect.Fragment{Raw: text}
	leaks := s.detector.Detect(fragment)

	result := ScanResult{
		Secrets: make([]string, 0, len(leaks)),
	}

	for _, leak := range leaks {
		s.log.Info("leak detected", "rule", leak.RuleID, "secret", truncate(leak.Secret))
		result.Secrets = append(result.Secrets, leak.Secret)
	}

	return result
}

// ScanRequestBody extracts the messages field from a JSON body and scans it.
// Falls back to scanning the entire body if no messages field exists.
func (s *Scanner) ScanRequestBody(body []byte) ScanResult {
	bodyStr := string(body)

	// Extract messages array if present, otherwise scan entire body
	// Its easier to deal with the full message as a string rather than parsing
	// content or text.
	textToScan := bodyStr
	if messages := gjson.Get(bodyStr, "messages"); messages.Exists() && messages.IsArray() {
		textToScan = messages.Raw
		s.log.Debug("scanning messages field", "length", len(textToScan))
	} else {
		s.log.Debug("no messages field, scanning entire body", "length", len(textToScan))
	}

	return s.Scan(textToScan)
}

// ScanAndReplaceRequestBody scans and replaces secrets in the request body by properly
// parsing the Anthropic API request structure. Returns the scan result and modified body.
// This is slower but safer than raw string scanning, as it only scans actual text content
// and avoids false positives from JSON structure.
// The issue with this is that any changes upstream in anthropic's response may potentially break this
func (s *Scanner) ScanAndReplaceRequestBody(body []byte, replacement string) (ScanResult, []byte, error) {
	// Try to unmarshal into MessageNewParams
	var params anthropic.MessageNewParams
	if err := json.Unmarshal(body, &params); err != nil {
		s.log.Debug("failed to parse, using string replacement", "error", err)
		result := s.ScanRequestBody(body)
		modifiedBody := body
		for _, secret := range result.Secrets {
			modifiedBody = []byte(strings.ReplaceAll(string(modifiedBody), secret, replacement))
		}
		return result, modifiedBody, nil
	}

	result := ScanResult{
		Secrets: make([]string, 0),
	}

	textScanned := 0

	// Process each message
	for i := range params.Messages {
		msg := &params.Messages[i]
		s.log.Debug("processing message", "index", i, "role", msg.Role)

		for j := range msg.Content {
			content := &msg.Content[j]
			s.log.Debug("processing content block", "message_index", i, "block_index", j)

			// Text blocks
			if content.OfText != nil {
				text := content.OfText.Text
				if text != "" {
					textScanned += len(text)
					scanResult := s.Scan(text)
					result.Secrets = append(result.Secrets, scanResult.Secrets...)

					// Replace secrets in-place
					for _, secret := range scanResult.Secrets {
						content.OfText.Text = strings.ReplaceAll(content.OfText.Text, secret, replacement)
					}
					s.log.Debug("scanned text block", "length", len(text), "secrets_found", len(scanResult.Secrets))
				}
			}

			// Tool use blocks - scan the input
			// The input is an any type, hence the need to marshall, we don't exactly know the
			// input?
			// quick ref https://github.com/anthropics/anthropic-sdk-go/blob/09e977d786cebc0edd2fb52ca18f809ca939ea47/message.go#L4140
			if content.OfToolUse != nil && content.OfToolUse.Input != nil {
				if inputJSON, err := json.Marshal(content.OfToolUse.Input); err == nil {
					textScanned += len(inputJSON)
					scanResult := s.Scan(string(inputJSON))
					result.Secrets = append(result.Secrets, scanResult.Secrets...)

					// Replace secrets in the input by unmarshaling, replacing, and remarshaling
					if len(scanResult.Secrets) > 0 {
						inputStr := string(inputJSON)
						for _, secret := range scanResult.Secrets {
							inputStr = strings.ReplaceAll(inputStr, secret, replacement)
						}
						var newInput any
						if err := json.Unmarshal([]byte(inputStr), &newInput); err == nil {
							content.OfToolUse.Input = newInput
						}
					}
					s.log.Debug("scanned tool_use input", "length", len(inputJSON), "secrets_found", len(scanResult.Secrets))
				}
			}

			// Tool result blocks
			// quick ref of the struct in messages.go
			// https://github.com/anthropics/anthropic-sdk-go/blob/09e977d786cebc0edd2fb52ca18f809ca939ea47/message.go#L3620
			if content.OfToolResult != nil {
				// Process each content block in the tool result
				for k := range content.OfToolResult.Content {
					toolResultContent := &content.OfToolResult.Content[k]

					// Handle text blocks in tool results
					if toolResultContent.OfText != nil {
						text := toolResultContent.OfText.Text
						if text != "" {
							textScanned += len(text)
							scanResult := s.Scan(text)
							result.Secrets = append(result.Secrets, scanResult.Secrets...)

							// Replace secrets in-place
							for _, secret := range scanResult.Secrets {
								toolResultContent.OfText.Text = strings.ReplaceAll(toolResultContent.OfText.Text, secret, replacement)
							}
							s.log.Debug("scanned tool_result text", "length", len(text), "secrets_found", len(scanResult.Secrets))
						}
					}
					// TODO: In tool result, there are other fields like documents and urls
					// should we scan them as well?
				}
			}
			// in messages.go, there are these other fields, just for reference as they may change
			//  type ContentBlockParamUnion struct {
			// 	OfText                *TextBlockParam                `json:",omitzero,inline"`
			// 	OfImage               *ImageBlockParam               `json:",omitzero,inline"`
			// 	OfDocument            *DocumentBlockParam            `json:",omitzero,inline"`
			// 	OfSearchResult        *SearchResultBlockParam        `json:",omitzero,inline"`
			// 	OfThinking            *ThinkingBlockParam            `json:",omitzero,inline"`
			// 	OfRedactedThinking    *RedactedThinkingBlockParam    `json:",omitzero,inline"`
			// 	OfToolUse             *ToolUseBlockParam             `json:",omitzero,inline"`
			// 	OfToolResult          *ToolResultBlockParam          `json:",omitzero,inline"`
			// 	OfServerToolUse       *ServerToolUseBlockParam       `json:",omitzero,inline"`
			// 	OfWebSearchToolResult *WebSearchToolResultBlockParam `json:",omitzero,inline"`
			// 	paramUnion
			// }
		}
	}

	// Process system prompt
	if params.System != nil {
		for i := range params.System {
			sysBlock := &params.System[i]
			if sysBlock.Text != "" {
				textScanned += len(sysBlock.Text)
				scanResult := s.Scan(sysBlock.Text)
				result.Secrets = append(result.Secrets, scanResult.Secrets...)

				// Replace secrets in system prompt
				for _, secret := range scanResult.Secrets {
					sysBlock.Text = strings.ReplaceAll(sysBlock.Text, secret, replacement)
				}
				s.log.Debug("scanned system prompt", "length", len(sysBlock.Text), "secrets_found", len(scanResult.Secrets))
			}
		}
	}

	// If no text was scanned, fall back to raw scan
	if textScanned == 0 {
		s.log.Debug("no structured content found, falling back to raw scan")
		result = s.ScanRequestBody(body)
		return result, body, nil
	}

	s.log.Debug("structured scan complete", "text_scanned", textScanned, "total_secrets", len(result.Secrets))

	// Marshal back to JSON
	modifiedBody, err := json.Marshal(params)
	if err != nil {
		s.log.Error("failed to marshal modified params", "error", err)
		return result, body, fmt.Errorf("marshal modified params: %w", err)
	}

	return result, modifiedBody, nil
}

// truncate returns a truncated version of the string for safe logging.
// If the string is shorter than 8, returns "********".
// Otherwise, shows first 2 chars + "****" + last 2 chars.
// ideally add it as a variable?
func truncate(s string) string {
	length := len(s)
	if length < 8 {
		return "********"
	}
	return s[:2] + "****" + s[length-2:]
}
