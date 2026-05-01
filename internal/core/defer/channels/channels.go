// Package channels implements multi-channel DEFER notification delivery.
//
// Each channel receives approval requests and can deliver resolution callbacks.
// Supported channels:
//   - PagerDuty: Critical priority DEFERs → PagerDuty incidents
//   - Microsoft Teams: Adaptive card with approve/deny buttons
//   - Email (SMTP): HTML email with approval links
//   - Telegram: Bot message with inline keyboard
//
// The existing Slack integration is in workflow.go. These channels
// extend the notification surface for enterprise deployments.
package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Notification is the platform-agnostic DEFER notification.
type Notification struct {
	Token      string `json:"token"`
	AgentID    string `json:"agent_id"`
	ToolID     string `json:"tool_id"`
	Reason     string `json:"reason"`
	Priority   string `json:"priority"`
	Deadline   string `json:"deadline"`
	ApproveURL string `json:"approve_url"` // callback URL for approval
	DenyURL    string `json:"deny_url"`    // callback URL for denial
}

// Channel is the interface for DEFER notification channels.
type Channel interface {
	Name() string
	Send(ctx context.Context, n Notification) error
}

// PagerDutyChannel sends critical DEFER notifications as PagerDuty incidents.
type PagerDutyChannel struct {
	routingKey string
	client     *http.Client
}

// NewPagerDutyChannel creates a new PagerDuty channel.
func NewPagerDutyChannel(routingKey string) *PagerDutyChannel {
	return &PagerDutyChannel{
		routingKey: routingKey,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *PagerDutyChannel) Name() string { return "pagerduty" }

func (c *PagerDutyChannel) Send(ctx context.Context, n Notification) error {
	payload := map[string]any{
		"routing_key":  c.routingKey,
		"event_action": "trigger",
		"dedup_key":    "faramesh-defer-" + n.Token,
		"payload": map[string]any{
			"summary":  fmt.Sprintf("Faramesh DEFER: %s → %s (%s)", n.AgentID, n.ToolID, n.Reason),
			"severity": pdSeverity(n.Priority),
			"source":   "faramesh-core",
			"custom_details": map[string]string{
				"token":    n.Token,
				"agent_id": n.AgentID,
				"tool_id":  n.ToolID,
				"reason":   n.Reason,
				"deadline": n.Deadline,
			},
		},
	}
	return c.post(ctx, "https://events.pagerduty.com/v2/enqueue", payload)
}

func (c *PagerDutyChannel) post(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("pagerduty: HTTP %d", resp.StatusCode)
	}
	return nil
}

func pdSeverity(priority string) string {
	switch priority {
	case "critical":
		return "critical"
	case "high":
		return "error"
	default:
		return "warning"
	}
}

// TeamsChannel sends DEFER notifications to Microsoft Teams via webhook.
type TeamsChannel struct {
	webhookURL string
	client     *http.Client
}

// NewTeamsChannel creates a new Microsoft Teams channel.
func NewTeamsChannel(webhookURL string) *TeamsChannel {
	return &TeamsChannel{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *TeamsChannel) Name() string { return "teams" }

func (c *TeamsChannel) Send(ctx context.Context, n Notification) error {
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": teamsColor(n.Priority),
		"summary":    "Faramesh DEFER Request",
		"sections": []map[string]any{
			{
				"activityTitle": fmt.Sprintf("DEFER: %s → %s", n.AgentID, n.ToolID),
				"facts": []map[string]string{
					{"name": "Token", "value": n.Token},
					{"name": "Priority", "value": n.Priority},
					{"name": "Reason", "value": n.Reason},
					{"name": "Deadline", "value": n.Deadline},
				},
			},
		},
		"potentialAction": []map[string]any{
			{
				"@type":  "HttpPOST",
				"name":   "Approve",
				"target": n.ApproveURL,
			},
			{
				"@type":  "HttpPOST",
				"name":   "Deny",
				"target": n.DenyURL,
			},
		},
	}
	body, err := json.Marshal(card)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func teamsColor(priority string) string {
	switch priority {
	case "critical":
		return "FF0000"
	case "high":
		return "FFA500"
	default:
		return "0078D7"
	}
}

// TelegramChannel sends DEFER notifications via Telegram Bot API.
type TelegramChannel struct {
	botToken string
	chatID   string
	client   *http.Client
}

// NewTelegramChannel creates a new Telegram channel.
func NewTelegramChannel(botToken, chatID string) *TelegramChannel {
	return &TelegramChannel{
		botToken: botToken,
		chatID:   chatID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *TelegramChannel) Name() string { return "telegram" }

func (c *TelegramChannel) Send(ctx context.Context, n Notification) error {
	text := fmt.Sprintf(
		"🚨 *Faramesh DEFER*\n\n"+
			"Agent: `%s`\nTool: `%s`\nPriority: *%s*\n"+
			"Reason: %s\nDeadline: %s\nToken: `%s`",
		n.AgentID, n.ToolID, n.Priority, n.Reason, n.Deadline, n.Token)

	payload := map[string]any{
		"chat_id":    c.chatID,
		"text":       text,
		"parse_mode": "Markdown",
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{
				{
					{"text": "✅ Approve", "callback_data": "approve:" + n.Token},
					{"text": "❌ Deny", "callback_data": "deny:" + n.Token},
				},
			},
		},
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.botToken)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// MultiChannel fans out notifications to multiple channels based on priority.
type MultiChannel struct {
	channels map[string][]Channel // priority → channels
	fallback []Channel
}

// NewMultiChannel creates a multi-channel dispatcher.
func NewMultiChannel() *MultiChannel {
	return &MultiChannel{
		channels: make(map[string][]Channel),
	}
}

// RegisterChannel registers a channel for a specific priority.
func (mc *MultiChannel) RegisterChannel(priority string, ch Channel) {
	mc.channels[priority] = append(mc.channels[priority], ch)
}

// RegisterFallback registers a channel that receives all notifications.
func (mc *MultiChannel) RegisterFallback(ch Channel) {
	mc.fallback = append(mc.fallback, ch)
}

// Send dispatches a notification to all channels matching its priority.
func (mc *MultiChannel) Send(ctx context.Context, n Notification) error {
	channels := mc.channels[n.Priority]
	channels = append(channels, mc.fallback...)
	var lastErr error
	for _, ch := range channels {
		if err := ch.Send(ctx, n); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
