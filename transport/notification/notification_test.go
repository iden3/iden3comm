package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/require"
)

func pushGatewaySuccessMock(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"device":{"ciphertext":"sIyhw8MsRzFTMXnPvvPnjpj38vVHK9z7w/DvHzX+i/68hSjWfSDjXUA49KopWexyoVsAhenS+AS7+JkatJ3+OTlNxUD+lFrAIJUE51qBiM7l7mmkAuryybUQmOgWJCbuUU2nsWFKzIvk2ZTxcMh5EoUxYV2/0HaTmYYTDkzCKQr/oVePlHbiKwG6XjjMCuNaooSAO7UlLduEZY9CjCWBahiJ7LPHq5+SMCSpA9DdxlYe5IDY7ZT0Yg8fmEAq5+ZGvPVDzk1SdXvZNtG/2yygb3ILrSHXN81ztJRPdsEjzctqWwIhP1zEncSMnNEY4vtxEc1red4PuNT6QX0EoP/aX4LdSGIgfM3KB6yjqKBOqgIGoTFih0h/YzcC42lv4oJw0t5obX+32FM8pzQBUoXMvV0F9WpNgDcN04F3/Su9GGRLFNLXApCtj2Mh4H0qnkjMzRMO42RTd3258HYH7U8xK48hpO0Wolt+rn3jrk/JXrVQqO/9EnhCu/PJL1+AoeVtTYL0zp57OWnIAXbW98MGg0pm0MpYwH51hmHx0YLH+4Fkqj30ydcZQhV3xtAVgvKfxQOwwNz2WhIefm+fwYLVAQB4SjUMOrRQYAos7PWgoc21I0QFu52dIA4IvYYBws2Vjb1LvssdFnrd4kUYbC7THdlWONfunbp9xgofzXTrj2g=","alg":"RS512"},"status":"success","reason":""}]`))
	}))
}
func pushGatewayRejectedMock(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"device":{"ciphertext":"kIyhw8MsRzFTMXnPvvPnjpj38vVHK9z7w/DvHzX+i/68hSjWfSDjXUA49KopWexyoVsAhenS+AS7+JkatJ3+OTlNxUD+lFrAIJUE51qBiM7l7mmkAuryybUQmOgWJCbuUU2nsWFKzIvk2ZTxcMh5EoUxYV2/0HaTmYYTDkzCKQr/oVePlHbiKwG6XjjMCuNaooSAO7UlLduEZY9CjCWBahiJ7LPHq5+SMCSpA9DdxlYe5IDY7ZT0Yg8fmEAq5+ZGvPVDzk1SdXvZNtG/2yygb3ILrSHXN81ztJRPdsEjzctqWwIhP1zEncSMnNEY4vtxEc1red4PuNT6QX0EoP/aX4LdSGIgfM3KB6yjqKBOqgIGoTFih0h/YzcC42lv4oJw0t5obX+32FM8pzQBUoXMvV0F9WpNgDcN04F3/Su9GGRLFNLXApCtj2Mh4H0qnkjMzRMO42RTd3258HYH7U8xK48hpO0Wolt+rn3jrk/JXrVQqO/9EnhCu/PJL1+AoeVtTYL0zp57OWnIAXbW98MGg0pm0MpYwH51hmHx0YLH+4Fkqj30ydcZQhV3xtAVgvKfxQOwwNz2WhIefm+fwYLVAQB4SjUMOrRQYAos7PWgoc21I0QFu52dIA4IvYYBws2Vjb1LvssdFnrd4kUYbC7THdlWONfunbp9xgofzXTrj2g=","alg":"RS512"},"status":"rejected","reason" :"Push message could have been rejected by an unstream gateway because they have expired or have never been valid"}]`))
	}))
}

func TestPushClient_Notify(t *testing.T) {

	mockPushServer := pushGatewaySuccessMock(t)
	defer mockPushServer.Close()
	mockPushServerRejector := pushGatewayRejectedMock(t)
	defer mockPushServerRejector.Close()
	id := "did:iden3:polygon:mumbai:115gD96EyyqQhLjjNQ6s5mHRMczRRute7nUDgCH9ot"
	pushService := verifiable.PushService{
		Service: verifiable.Service{
			ID:              fmt.Sprintf("%s#push", id),
			Type:            verifiable.PushNotificationServiceType,
			ServiceEndpoint: mockPushServer.URL,
		},
		Metadata: verifiable.PushMetadata{
			Devices: []verifiable.EncryptedDeviceMetadata{verifiable.EncryptedDeviceMetadata{
				Ciphertext: "sIyhw8MsRzFTMXnPvvPnjpj38vVHK9z7w/DvHzX+i/68hSjWfSDjXUA49KopWexyoVsAhenS+AS7+JkatJ3+OTlNxUD+lFrAIJUE51qBiM7l7mmkAuryybUQmOgWJCbuUU2nsWFKzIvk2ZTxcMh5EoUxYV2/0HaTmYYTDkzCKQr/oVePlHbiKwG6XjjMCuNaooSAO7UlLduEZY9CjCWBahiJ7LPHq5+SMCSpA9DdxlYe5IDY7ZT0Yg8fmEAq5+ZGvPVDzk1SdXvZNtG/2yygb3ILrSHXN81ztJRPdsEjzctqWwIhP1zEncSMnNEY4vtxEc1red4PuNT6QX0EoP/aX4LdSGIgfM3KB6yjqKBOqgIGoTFih0h/YzcC42lv4oJw0t5obX+32FM8pzQBUoXMvV0F9WpNgDcN04F3/Su9GGRLFNLXApCtj2Mh4H0qnkjMzRMO42RTd3258HYH7U8xK48hpO0Wolt+rn3jrk/JXrVQqO/9EnhCu/PJL1+AoeVtTYL0zp57OWnIAXbW98MGg0pm0MpYwH51hmHx0YLH+4Fkqj30ydcZQhV3xtAVgvKfxQOwwNz2WhIefm+fwYLVAQB4SjUMOrRQYAos7PWgoc21I0QFu52dIA4IvYYBws2Vjb1LvssdFnrd4kUYbC7THdlWONfunbp9xgofzXTrj2g=",
				Alg:        "RS512",
			}},
		},
	}
	msg := []byte(`"here can be a json protocol message from issuer"`)

	t.Run("success", func(t *testing.T) {
		doc := verifiable.DIDDocument{
			Context: []string{`https://www.w3.org/ns/did/v1`},
			ID:      id,
			Service: []interface{}{pushService},
		}
		dd, _ := json.Marshal(doc)
		fmt.Println(string(dd))

		resp, err := Notify(context.Background(), msg, doc, nil)
		require.NoError(t, err, ErrNoDeviceInfoInPushService)
		require.Len(t, resp.Devices, 1)
		require.Equal(t, DeviceNotificationStatusSuccess, resp.Devices[0].Status)

	})

	t.Run("no device info in push service", func(t *testing.T) {

		pushService.Metadata = verifiable.PushMetadata{}
		doc := verifiable.DIDDocument{
			Context: []string{`https://www.w3.org/ns/did/v1`},
			ID:      id,
			Service: []interface{}{pushService},
		}
		_, err := Notify(context.Background(), msg, doc, nil)
		require.ErrorIs(t, err, ErrNoDeviceInfoInPushService)
	})

	t.Run("no push service", func(t *testing.T) {

		pushService.Metadata = verifiable.PushMetadata{}
		doc := verifiable.DIDDocument{
			Context: []string{`https://www.w3.org/ns/did/v1`},
			ID:      id,
			Service: []interface{}{},
		}
		_, err := Notify(context.Background(), msg, doc, nil)
		require.ErrorIs(t, err, ErrNoPushService)
	})

	t.Run("rejected device", func(t *testing.T) {
		pushService.ServiceEndpoint = mockPushServerRejector.URL
		pushService.Metadata.Devices = []verifiable.EncryptedDeviceMetadata{{
			Ciphertext: "kIyhw8MsRzFTMXnPvvPnjpj38vVHK9z7w/DvHzX+i/68hSjWfSDjXUA49KopWexyoVsAhenS+AS7+JkatJ3+OTlNxUD+lFrAIJUE51qBiM7l7mmkAuryybUQmOgWJCbuUU2nsWFKzIvk2ZTxcMh5EoUxYV2/0HaTmYYTDkzCKQr/oVePlHbiKwG6XjjMCuNaooSAO7UlLduEZY9CjCWBahiJ7LPHq5+SMCSpA9DdxlYe5IDY7ZT0Yg8fmEAq5+ZGvPVDzk1SdXvZNtG/2yygb3ILrSHXN81ztJRPdsEjzctqWwIhP1zEncSMnNEY4vtxEc1red4PuNT6QX0EoP/aX4LdSGIgfM3KB6yjqKBOqgIGoTFih0h/YzcC42lv4oJw0t5obX+32FM8pzQBUoXMvV0F9WpNgDcN04F3/Su9GGRLFNLXApCtj2Mh4H0qnkjMzRMO42RTd3258HYH7U8xK48hpO0Wolt+rn3jrk/JXrVQqO/9EnhCu/PJL1+AoeVtTYL0zp57OWnIAXbW98MGg0pm0MpYwH51hmHx0YLH+4Fkqj30ydcZQhV3xtAVgvKfxQOwwNz2WhIefm+fwYLVAQB4SjUMOrRQYAos7PWgoc21I0QFu52dIA4IvYYBws2Vjb1LvssdFnrd4kUYbC7THdlWONfunbp9xgofzXTrj2g=",
			Alg:        "RS512",
		}}

		doc := verifiable.DIDDocument{
			Context: []string{`https://www.w3.org/ns/did/v1`},
			ID:      id,
			Service: []interface{}{pushService},
		}
		resp, err := Notify(context.Background(), msg, doc, nil)
		require.NoError(t, err, ErrNoDeviceInfoInPushService)
		require.Len(t, resp.Devices, 1)
		require.Equal(t, DeviceNotificationStatusRejected, resp.Devices[0].Status)

	})

}
