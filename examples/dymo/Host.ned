package org.mixim.examples.dymo;

import org.mixim.modules.nic.Nic80211;
import org.mixim.modules.mobility.ConstSpeedMobility;
import org.mixim.base.modules.BaseUtility;
import mixnet.modules.MixnetBridge;
import inet.transport.udp.UDP;
import inet.nodes.inet.NetworkLayer;
import inet.networklayer.ipv4.RoutingTable;
import inet.networklayer.common.InterfaceTable;
import inet.base.NotificationBoard;
import inet.applications.udpapp.UDPBasicApp;
import inet.applications.dymo.DYMO;


// This host is an example on how a host with INET network stack
// can be equipped with mobility- and wireless-modules from MiXiM. 
//
// It contains an INET network stack and a MiXiM 802.11 NIC (connected
// by the MixnetBridge module) as well as a mobility-module from MiXiM.
module Host
{
    parameters:
        @node();
        @labels(node,ethernet-node,wireless-node);
        @display("i=device/wifilaptop;bgb=462,483");

    gates:
        input radioIn @directIn;

    submodules:
        utility: BaseUtility {
            @display("p=147,41");
        }
        mobility: ConstSpeedMobility {
            parameters:
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
                @display("p=304,47;i=block/fork;q=queue");
        }
        udpapp: UDPBasicApp {
            parameters:
                @display("i=block/app;p=384,47");
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
                ifIn[1];
                ifOut[1];
        }
        bridge: MixnetBridge {
            @display("p=217,332");
        }
        wlan: Nic80211 {
            parameters:
                @display("p=217,427;q=queue");
        }

    connections allowunconnected:
        udpapp.udpOut --> udp.appIn++;
        udpapp.udpIn <-- udp.appOut++;

        dymo.udp$o --> udp.appIn++;
        dymo.udp$i <-- udp.appOut++;

        udp.ipOut --> networkLayer.udpIn;
        udp.ipIn <-- networkLayer.udpOut;

        radioIn --> wlan.radioIn;
        bridge.upperGateOut --> networkLayer.ifIn[0];
        bridge.upperGateIn <-- networkLayer.ifOut[0];

        wlan.upperGateOut --> { @display("ls=black;m=m,25,50,25,0"); } --> bridge.lowerGateIn;
        wlan.upperGateIn <-- { @display("ls=black;m=m,15,50,15,0"); } <-- bridge.lowerGateOut;
        wlan.upperControlOut --> { @display("ls=red;m=m,75,50,75,0"); } --> bridge.lowerControlIn;
        wlan.upperControlIn <-- { @display("ls=red;m=m,85,0,85,0"); } <-- bridge.lowerControlOut;
}

