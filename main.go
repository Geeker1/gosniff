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

func handleHome(w http.ResponseWriter, r *http.Request) {
	json.SendJson(w, "Working root endppoint of the packet sniffer")
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
	json.GetJson(r, &chosenInterfaces)

	json.SendJson(w, JsonMessage{Message: "Recieved"})

	pcapHandler := &packets.PcapHandler{}
	pcapMessage := &packets.SniffMessage{
		Message: packetChan,
	}
	for _, i := range chosenInterfaces {
		go packets.StartPacketSniffing(pcapHandler, i, pcapMessage)
	}

	if <-c == "kill" {
		log.Println("Kill message recieved... stopped packet sniffing")
	}
}

func recievePackets(w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)

	for {
		packet := <-packetChan

		// conn.WriteMessage(1, []byte(fmt.Sprintf("%v", result)))
		conn.WriteJSON(packet)
	}
}

func killPackets(w http.ResponseWriter, r *http.Request) {
	log.Println("Recieve kill signal")
	c <- "kill"
	json.SendJson(w, JsonMessage{Message: "Done"})
}

func main() {
	port := *flag.String("port", "8080", "Application port")
	flag.Parse()

	r := mux.NewRouter()

	r.HandleFunc("/", handleHome).Methods("GET")
	r.HandleFunc("/active-interfaces", getActiveInterfaces).Methods("GET")
	r.HandleFunc("/start-sniffer", startSniffer).Methods("POST")
	r.HandleFunc("/recieve-packets", recievePackets).Methods("GET")
	r.HandleFunc("/kill-packets", killPackets).Methods("POST")

	log.Println("Application listening on port ", port)
	http.ListenAndServe(":"+port, r)
}
