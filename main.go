package main

import (
	"flag"
	"fmt"
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

var packetChan = make(chan gopacket.Packet)
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
		packets.StartPacketSniffing(i, packetChan)
		// packet := <-packetChan

		// if packet == nil {
		// 	json.SendJson(w, PacketsData{})
		// 	return
		// }

		// result := PacketsData{
		// 	Dst: packet.NetworkLayer().NetworkFlow().Dst().String(),
		// 	Src: packet.NetworkLayer().NetworkFlow().Src().String(),
		// }

		// if err := json.SendJson(w, result); err != nil {
		// 	log.Panic(err)
		// }
	}
}

func recievePackets(w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)

	for {
		packet := <-packetChan

		if packet == nil {
			msg := []byte(fmt.Sprintf("%v", PacketsData{}))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				log.Panic(err)
				return
			}
			return
		}

		result := PacketsData{
			Dst: packet.NetworkLayer().NetworkFlow().Dst().String(),
			Src: packet.NetworkLayer().NetworkFlow().Src().String(),
		}

		conn.WriteJSON(result)
	}
	// if err := json.SendJson(w, result); err != nil {
	// 	log.Panic(err)
	// }
}

func main() {
	port := *flag.String("port", "8080", "Application port")
	flag.Parse()

	r := mux.NewRouter()

	r.HandleFunc("/", handleHome).Methods("GET")
	r.HandleFunc("/active-interfaces", getActiveInterfaces).Methods("GET")
	r.HandleFunc("/start-sniffer", startSniffer).Methods("POST")
	r.HandleFunc("/recieve-packets", recievePackets).Methods("GET")

	log.Println("Application listening on port ", port)
	http.ListenAndServe(":"+port, r)
}
