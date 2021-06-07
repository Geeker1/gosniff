package json

import (
	"encoding/json"
	"net/http"
)

func SendJson(w http.ResponseWriter, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(data)
}

func GetJson(r *http.Request, dst interface{}) error {
	return json.NewDecoder(r.Body).Decode(&dst)
}
