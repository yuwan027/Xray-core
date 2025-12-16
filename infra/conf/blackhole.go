package conf

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/blackhole"
	"google.golang.org/protobuf/proto"
)

type NoneResponse struct{}

func (*NoneResponse) Build() (proto.Message, error) {
	return new(blackhole.NoneResponse), nil
}

type HTTPResponse struct{}

func (*HTTPResponse) Build() (proto.Message, error) {
	return new(blackhole.HTTPResponse), nil
}

type HTTPCustomResponse struct {
	StatusCode int32
}

func (r *HTTPCustomResponse) Build() (proto.Message, error) {
	return &blackhole.HTTPCustomResponse{
		StatusCode: r.StatusCode,
	}, nil
}

type TLSAlertResponse struct {
	AlertCode int32
}

func (r *TLSAlertResponse) Build() (proto.Message, error) {
	return &blackhole.TLSAlertResponse{
		AlertCode: r.AlertCode,
	}, nil
}

type BlackholeConfig struct {
	Response json.RawMessage `json:"response"`
}

func (v *BlackholeConfig) Build() (proto.Message, error) {
	config := new(blackhole.Config)
	if v.Response != nil {
		response, _, err := loadBlackholeResponse(v.Response)
		if err != nil {
			return nil, errors.New("Config: Failed to parse Blackhole response config.").Base(err)
		}
		responseSettings, err := response.(Buildable).Build()
		if err != nil {
			return nil, err
		}
		config.Response = serial.ToTypedMessage(responseSettings)
	}

	return config, nil
}

func loadBlackholeResponse(raw []byte) (interface{}, string, error) {
	var obj struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, "", err
	}

	id := strings.ToLower(obj.Type)

	// Handle http-xxx format (e.g., http-200, http-301, http-404)
	if strings.HasPrefix(id, "http-") {
		statusStr := strings.TrimPrefix(id, "http-")
		statusCode, err := strconv.Atoi(statusStr)
		if err != nil {
			return nil, id, errors.New("invalid HTTP status code: ", statusStr).Base(err)
		}
		return &HTTPCustomResponse{StatusCode: int32(statusCode)}, id, nil
	}

	// Handle tls and tls-xxx format (e.g., tls, tls-40, tls-70)
	if id == "tls" {
		return &TLSAlertResponse{AlertCode: 40}, id, nil // default: handshake_failure
	}
	if strings.HasPrefix(id, "tls-") {
		alertStr := strings.TrimPrefix(id, "tls-")
		alertCode, err := strconv.Atoi(alertStr)
		if err != nil {
			return nil, id, errors.New("invalid TLS alert code: ", alertStr).Base(err)
		}
		return &TLSAlertResponse{AlertCode: int32(alertCode)}, id, nil
	}

	// Fall back to standard config loader for "none" and "http"
	return configLoader.Load(raw)
}

var configLoader = NewJSONConfigLoader(
	ConfigCreatorCache{
		"none": func() interface{} { return new(NoneResponse) },
		"http": func() interface{} { return new(HTTPResponse) },
	},
	"type",
	"")
