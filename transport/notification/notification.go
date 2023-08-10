package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/pkg/errors"
)

var (
	// ErrNoDeviceInfoInPushService is an error when push service in did document doesn't contain device metadata
	ErrNoDeviceInfoInPushService = errors.New("no devices in push service")
	// ErrNoPushService is an error when did document doesn't contain push service
	ErrNoPushService = errors.New("no push service in did document")
)

// DeviceNotificationStatus is a notification status
type DeviceNotificationStatus string

const (
	// DeviceNotificationStatusSuccess is for pushes that are sent to APNS / FCM
	DeviceNotificationStatusSuccess DeviceNotificationStatus = "success"
	// DeviceNotificationStatusRejected is for pushes that are rejected by APNS / FCM
	DeviceNotificationStatusRejected DeviceNotificationStatus = "rejected"
	// DeviceNotificationStatusFailed is for pushes that were not sent
	DeviceNotificationStatusFailed DeviceNotificationStatus = "failed"
)

// UserNotificationResult is a result of push gateway
type UserNotificationResult struct {
	Devices []DeviceNotificationResult `json:"devices"`
}

// DeviceNotificationResult is a result of push gateway
type DeviceNotificationResult struct {
	Device verifiable.EncryptedDeviceMetadata `json:"device"`
	Status DeviceNotificationStatus           `json:"status"`
	Reason string                             `json:"reason"`
}

type notification struct {
	Metadata verifiable.PushMetadata `json:"metadata"`
	Message  json.RawMessage         `json:"message"`
}

// Notify sends push notification to iden3 push gateway. If httpClient is nil, http.DefaultClient is used.
func Notify(
	ctx context.Context,
	msg json.RawMessage,
	pushService verifiable.PushService,
	httpClient *http.Client) (*UserNotificationResult, error) {

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	if len(pushService.Metadata.Devices) == 0 {
		return nil, ErrNoDeviceInfoInPushService
	}

	reqData := notification{
		Metadata: pushService.Metadata,
		Message:  msg,
	}
	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, pushService.ServiceEndpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			log.Println(err)
		}
	}()

	var result []DeviceNotificationResult
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &UserNotificationResult{Devices: result}, nil
}
