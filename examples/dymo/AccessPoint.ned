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

import inet.base.NotificationBoard;
import inet.linklayer.ethernet.EthernetInterface;
import inet.linklayer.mf80211.Nic80211;
import inet.mobility.LinearMobility;
import inet.networklayer.common.InterfaceTable;
import inet.networklayer.ipv4.RoutingTable;
import inet.nodes.inet.NetworkLayer;
import inet.transport.udp.UDP;
import inet.applications.dymo.DYMO;

//
// Models a bridge between Wireless and Ethernet running DYMO
//
module AccessPoint
{
    parameters:

        @display("bgb=424,541");
    gates:
        input radioIn;
        inout lan;

    submodules:
        notificationBoard: NotificationBoard {
            parameters:
                @display("p=140,46;i=block/control");
        }
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=140,358;i=block/table");
        }
        mobility: LinearMobility {
            parameters:
                speed = 0;
                angle = 0;
                acceleration = 0;
                updateInterval = 0;
                @display("p=60,467;i=block/cogwheel");
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
                @display("p=280,143;i=block/fork;q=queue");
        }
        udp: UDP {
            parameters:
                @display("p=280,250;i=block/transport");
        }
        networkLayer: NetworkLayer {
            parameters:
                proxyARP = false;
                @display("p=280,359;i=block/fork;q=queue");
            gates:
                ifIn[2];
                ifOut[2];
        }
        eth: EthernetInterface {
            parameters:
                @display("p=344,470,row,90;q=txQueue;i=block/ifcard");
        }
        wlan: Nic80211 {
            parameters:
                @display("p=216,469;q=queue;i=block/ifcard");
        }
    connections allowunconnected:
        udp.appOut++ --> dymo.udp$i;
        udp.appIn++ <-- dymo.udp$o;

        networkLayer.udpOut --> udp.ipIn;
        networkLayer.udpIn <-- udp.ipOut;

        eth.netwOut --> networkLayer.ifIn[1];
        eth.netwIn <-- networkLayer.ifOut[1];

        wlan.uppergateOut --> networkLayer.ifIn[0];
        wlan.uppergateIn <-- networkLayer.ifOut[0];

        eth.phys <--> lan;

        radioIn --> wlan.radioIn;

}

