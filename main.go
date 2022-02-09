package main

import (
	"bufio"
	"fmt"

	"golang.org/x/sys/windows"

	"os"

	"inet.af/netaddr"
	"inet.af/wf"
)

func main() {
	fmt.Println("vim-go")

	session, err := wf.New(&wf.Options{
		Name:    "my WFP session",
		Dynamic: true,
	})
	if err != nil {
		panic(err)
	}
	guid, _ := windows.GenerateGUID()
	sublayerID := wf.SublayerID(guid)

	session.AddSublayer(&wf.Sublayer{
		ID:     sublayerID,
		Name:   "Default route killswitch",
		Weight: 0xffff, // the highest possible weight
	})

	layers := []wf.LayerID{
		wf.LayerALEAuthRecvAcceptV4,
		// wf.LayerALEAuthRecvAcceptV6,
		wf.LayerALEAuthConnectV4,
		// wf.LayerALEAuthConnectV6,
	}

	// Figure Out Nats Port, BOSH IP and Bosh Agent AppID
	natsPort := uint16(4222)
	appId, err := wf.AppID("C:\\bosh\\bosh-agent.exe")
	if err != nil {
		panic(err)
	}
	boshIpString := "10.0.16.5"
	boshIp, err := netaddr.ParseIP(boshIpString)
	if err != nil {
		panic(err)
	}
	prefix, err := boshIp.Prefix(32)
	// ipRange, err := netaddr.ParseIPRange(fmt.Sprintf("%v-%v", boshIpString, "10.0.16.6"))
	// tried matching ipRange, result is that toCondition0 throws `Add Rule fwpmFilterAdd0 Err: An FWP_RANGE is not valid`

	if err != nil {
		panic(err)
	}
	fmt.Printf("AppID: %s \n", appId)

	for _, layer := range layers {
		guid, err := windows.GenerateGUID()
		if err != nil {
			panic(err)
		}
		err = session.AddRule(&wf.Rule{
			ID:       wf.RuleID(guid),
			Name:     "Allow traffic to remote bosh nats for bosh-agent app id",
			Layer:    layer,
			Sublayer: sublayerID,
			Weight:   1000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypePrefix,
					Value: prefix,
				},
				{
					Field: wf.FieldALEAppID,
					Op:    wf.MatchTypeEqual,
					Value: appId,
				},
				{
					Field: wf.FieldIPRemotePort,
					Op:    wf.MatchTypeEqual,
					Value: natsPort,
				},
			},
			Action: wf.ActionBlock,
		})
		if err != nil {
			panic(fmt.Errorf(" %s", err))
		}
	}
	fmt.Println("Simple Shell")
	fmt.Println("---------------------")
	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

}

// session.AddRule(&wf.Rule{
// 	ID:       wf.RuleID(guid),
// 	Name:     "Allow DHCP",
// 	Layer:    wf.LayerALEAuthRecvAcceptV4,
// 	Sublayer: sublayerID,
// 	Weight:   900,
// 	Conditions: []*wf.Match{
// 		&wf.Match{
// 			Field: wf.FieldIPProtocol,
// 			Op:    wf.MatchTypeEqual,
// 			Value: wf.IPProtoTCP,
// 		},
// 		&wf.Match{
// 			Field: wf.FieldIPLocalPort,
// 			Op:    wf.MatchTypeEqual,
// 			Value: uint16(68), // DHCP client port
// 		},
// 	},
// 	Action: wf.ActionPermit,
// })
