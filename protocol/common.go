package protocol

import (
	"encoding/json"
	"reflect"
)

func commonMarshal(m any) ([]byte, error) {
	t := reflect.ValueOf(m)
	v := t.FieldByName("BasicMessage")

	b, err := json.Marshal(v.Interface())
	if err != nil {
		return nil, err
	}
	var o = map[string]any{}
	err = json.Unmarshal(b, &o)
	if err != nil {
		return nil, err
	}
	v = t.FieldByName("Body")

	var body json.RawMessage
	body, err = json.Marshal(v.Interface())
	if err != nil {
		return nil, err
	}
	o["body"] = body

	return json.Marshal(o)
}
