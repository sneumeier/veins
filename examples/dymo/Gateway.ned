package org.mixim.examples.dymo;

import org.mixim.modules.mobility.ConstSpeedMobility;
import org.mixim.base.modules.BaseUtility;
import mixnet.modules.MixnetBridge;
import inet.transport.udp.UDP;
import inet.nodes.inet.NetworkLayer;
import inet.networklayer.ipv4.RoutingTable;
import inet.networklayer.common.InterfaceTable;
import inet.linklayer.ethernet.EthernetInterface;
import inet.base.NotificationBoard;
import inet.applications.udpapp.UDPSink;
import inet.applications.dymo.DYMO;


//
// Models an Internet Gateway running DYMO on Ethernet
//
module Gateway
{
    parameters:
        @node();
        @labels(node,ethernet-node,wireless-node);
        @display("i=device/wifilaptop;bgb=462,483");

    gates:
        inout ethg @labels(EtherFrame-conn);

    submodules:
        utility: BaseUtility {
            @display("p=147,41");
        }
        mobility: ConstSpeedMobility {
            parameters:
                @display("p=147,128");
                speed = 0;
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
        udpapp: UDPSink {
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
                ifIn[2];
                ifOut[2];
        }

        eth[1]: EthernetInterface {
            parameters:
                @display("p=404,427,row,90;q=txQueue");
        }

    connections allowunconnected:
        udp.appOut++ --> dymo.udp$i;
        udp.appIn++ <-- dymo.udp$o;

        udpapp.udpOut --> udp.appIn++;
        udpapp.udpIn <-- udp.appOut++;

        udp.ipOut --> networkLayer.udpIn;
        udp.ipIn <-- networkLayer.udpOut;

        ethg <--> eth[0].phys;
        eth[0].netwOut --> networkLayer.ifIn[0];
        eth[0].netwIn <-- networkLayer.ifOut[0];
}

