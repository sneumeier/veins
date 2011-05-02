//
//  Copyright (C) 2006,2007 Christoph Sommer <christoph.sommer@informatik.uni-erlangen.de>
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

package inet.examples.dymo;

import inet.applications.udpapp.UDPSink;
import inet.base.NotificationBoard;
import inet.linklayer.ethernet.EthernetInterface;
import inet.networklayer.common.InterfaceTable;
import inet.networklayer.ipv4.RoutingTable;
import inet.nodes.inet.NetworkLayer;
import inet.transport.udp.UDP;
import inet.applications.dymo.DYMO;

//
// Models an Internet Gateway running DYMO on Ethernet
//
module Gateway
{
    parameters:
        @display("bgb=424,541");
    gates:
        inout ethg;

    submodules:
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=140,358;i=block/table");
        }
        notificationBoard: NotificationBoard {
            parameters:
                @display("p=140,462;i=block/control");
        }
        routingTable: RoutingTable {
            parameters:
                IPForward = true;
                routerId = "";
                routingFile = "";
                @display("p=60,358;i=block/table");
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
                @display("p=384,146;i=block/transport");
        }
        networkLayer: NetworkLayer {
            parameters:
                proxyARP = false;
                @display("p=304,327;i=block/fork;q=queue");
            gates:
                ifIn[1];
                ifOut[1];
        }
        eth: EthernetInterface {
            parameters:
                @display("p=304,461,row,90;q=txQueue;i=block/ifcard");
        }
    connections allowunconnected:
        udp.appOut++ --> udpapp.udpIn;
        udp.appIn++ <-- udpapp.udpOut;

        udp.appOut++ --> dymo.udp$i;
        udp.appIn++ <-- dymo.udp$o;

        networkLayer.udpOut --> udp.ipIn;
        networkLayer.udpIn <-- udp.ipOut;

        eth.netwOut --> networkLayer.ifIn[0];
        eth.netwIn <-- networkLayer.ifOut[0];

        eth.phys <--> ethg;

}

