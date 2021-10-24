package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/Geeker1/gosniff/json"
	"github.com/Geeker1/gosniff/packets"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type ChosenInterface struct {
	DeviceName string
}

type JsonMessage struct {
	Message string
}

var packetChan = make(chan packets.PacketsData)
var c = make(chan string)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func getActiveInterfaces(w http.ResponseWriter, r *http.Request) {
	pcapHandler := &packets.PcapHandler{}
	devs, err := pcapHandler.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}

	var devNames []string

	for _, dev := range devs {
		devNames = append(devNames, dev.Name)
	}

	json.SendJson(w, devNames)
}

func startSniffer(w http.ResponseWriter, r *http.Request) {
	var chosenInterfaces []string

	conn, _ := upgrader.Upgrade(w, r, nil)

	err := conn.ReadJSON(&chosenInterfaces)

	if err != nil {
		log.Println("Error reading JSON from connection.", err)
		conn.Close()
	}

	pcapHandler := &packets.PcapHandler{}
	pcapMessage := &packets.SniffMessage{
		Message: packetChan,
	}
	for _, i := range chosenInterfaces {
		go packets.StartPacketSniffing(pcapHandler, i, pcapMessage)
	}

	for {
		packet := <-packetChan
		conn.WriteJSON(packet)
	}
}

func main() {
	port := *flag.String("port", "8080", "Application port")
	flag.Parse()

	r := mux.NewRouter()

	r.HandleFunc("/active-interfaces", getActiveInterfaces).Methods("GET")
	r.HandleFunc("/start-sniffer", startSniffer)

	log.Println("Application listening on port ", port)
	http.ListenAndServe(":"+port, r)
}
