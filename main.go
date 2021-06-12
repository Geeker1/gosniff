package main

import (
	"flag"
	"gosniff/json"
	"gosniff/packets"
	"log"
	"net/http"

	"github.com/google/gopacket"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type ChosenInterface struct {
	DeviceName string
}

type PacketsData struct {
	Dst string
	Src string
}

type JsonMessage struct {
	Message string
}

var packetChan = make(chan gopacket.Packet)
var dnsChan = make(chan packets.DNS_DATA)
var c = make(chan string)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	json.SendJson(w, "Working root endppoint of the packet sniffer")
}

func getActiveInterfaces(w http.ResponseWriter, r *http.Request) {
	devs, err := packets.FindAllDevices()
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


	for _, i := range chosenInterfaces {
		go packets.StartPacketSniffing(i, packetChan)
	}

	if <-c == "kill" {
		log.Println("Kill message recieved... stopped packet sniffing")
	}

	json.SendJson(w, JsonMessage{Message: "Recieved"})
}

func recievePackets(w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)

	for {
		packet := <-packetChan

		if packet == nil {
			// msg := []byte(fmt.Sprintf("%v", PacketsData{}))
			// if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			// 	log.Panic(err)
			// 	return
			// }
			log.Println("Empty packet")
		}

		if packet != nil {
			result := PacketsData{
				Dst: packet.NetworkLayer().NetworkFlow().Dst().String(),
				Src: packet.NetworkLayer().NetworkFlow().Src().String(),
			}

			// conn.WriteMessage(1, []byte(fmt.Sprintf("%v", result)))
			conn.WriteJSON(result)
		}
	}
}

func killPackets(w http.ResponseWriter, r *http.Request) {
	log.Println("Recieve kill signal")
	c <- "kill"
	json.SendJson(w, JsonMessage{Message: "Done"})
}

func recieveDNSPackets(w http.ResponseWriter, r *http.Request) {
	log.Println("Process DNS questions")

	conn, _ := upgrader.Upgrade(w, r, nil)

	for {
		dnsData := <- dnsChan

		conn.WriteJSON(dnsData)
	}

}

func startDNSSniffing(w http.ResponseWriter, r *http.Request) {
	var chosenInterfaces []string
	json.GetJson(r, &chosenInterfaces)

	for _, i := range chosenInterfaces {
		go packets.GetDNSPackets(i, dnsChan)
	}

	if <-c == "kill" {
		log.Println("Kill message recieved... stopped packet sniffing")
	}

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
	r.HandleFunc("/start-dns", startDNSSniffing).Methods("POST")
	r.HandleFunc("/listen-dns", recieveDNSPackets).Methods("GET")

	log.Println("Application listening on port ", port)
	http.ListenAndServe(":"+port, r)
}
