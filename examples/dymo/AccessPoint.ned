package org.mixim.examples.dymo;

import org.mixim.modules.nic.Nic80211;
import org.mixim.modules.mobility.ConstSpeedMobility;
import org.mixim.base.modules.BaseUtility;
import mixnet.modules.MixnetBridge;
import inet.transport.udp.UDP;
import inet.nodes.inet.NetworkLayer;
import inet.networklayer.ipv4.RoutingTable;
import inet.networklayer.common.InterfaceTable;
import inet.linklayer.ethernet.EthernetInterface;
import inet.base.NotificationBoard;
import inet.applications.dymo.DYMO;


//
// Models a bridge between Wireless and Ethernet running DYMO
//
module AccessPoint
{
    parameters:
        @node();
        @labels(node,ethernet-node,wireless-node);
        @display("i=device/wifilaptop;bgb=462,483");

    gates:
        inout ethg @labels(EtherFrame-conn);
        input radioIn @directIn;

    submodules:
        utility: BaseUtility {
            @display("p=147,41");
        }
        mobility: ConstSpeedMobility {
            parameters:
                speed = 0;
                @display("p=147,128");
        }
        notificationBoard: NotificationBoard {
            parameters:
                @display("p=60,41");
        }
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=60,200");
        }
        routingTable: RoutingTable {
            parameters:
                IPForward = true;
                routerId = "";
                routingFile = "";
                @display("p=60,262");
        }
        dymo: DYMO {
            parameters:
                @display("p=280,143;i=block/fork;q=queue");
        }
        udp: UDP {
            parameters:
                @display("p=388,154");
        }
        networkLayer: NetworkLayer {
            parameters:
                proxyARP = false;
                @display("p=316,247;q=queue");
            gates:
                ifIn[3];
                ifOut[3];
        }
        eth: EthernetInterface {
            parameters:
                @display("p=404,427,row,90;q=txQueue");
        }
        bridge: MixnetBridge {
            @display("p=217,332");
        }
        wlan: Nic80211 {
            parameters:
                @display("p=217,427;q=queue");
        }

    connections allowunconnected:
        udp.appOut++ --> dymo.udp$i;
        udp.appIn++ <-- dymo.udp$o;

        udp.ipOut --> networkLayer.udpIn;
        udp.ipIn <-- networkLayer.udpOut;

        ethg <--> eth.phys;
        eth.netwOut --> networkLayer.ifIn[0];
        eth.netwIn <-- networkLayer.ifOut[0];

        radioIn --> wlan.radioIn;
        bridge.upperGateOut --> networkLayer.ifIn[1];
        bridge.upperGateIn <-- networkLayer.ifOut[1];

        wlan.upperGateOut --> { @display("ls=black;m=m,25,50,25,0"); } --> bridge.lowerGateIn;
        wlan.upperGateIn <-- { @display("ls=black;m=m,15,50,15,0"); } <-- bridge.lowerGateOut;
        wlan.upperControlOut --> { @display("ls=red;m=m,75,50,75,0"); } --> bridge.lowerControlIn;
        wlan.upperControlIn <-- { @display("ls=red;m=m,85,0,85,0"); } <-- bridge.lowerControlOut;
}

