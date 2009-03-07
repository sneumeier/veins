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

import inet.nodes.ethernet.EtherSwitch;
import inet.world.ChannelControl;

network Scenario
{
    parameters:
        double accessPoints;
        double hosts;
        double playgroundSizeX;
        double playgroundSizeY;
    submodules:
        channelcontrol: ChannelControl {
            parameters:
                playgroundSizeX = playgroundSizeX;
                playgroundSizeY = playgroundSizeY;
                @display("p=44,-46;i=misc/sun");
        }
        host[hosts]: Host {
            parameters:
                @display("i=device/wifilaptop_vs");
        }
        ap[accessPoints]: AccessPoint {
            parameters:
                @display("i=device/antennatower_vs");
        }
        switch: EtherSwitch {
            parameters:
                @display("p=-40,38;i=device/switch_s");
            gates:
                ethg[accessPoints+1];
        }
        gateway: Gateway {
            parameters:
                @display("p=-40,-46;i=device/router_s");
        }
    connections allowunconnected:
        for i=0..accessPoints-1 {
            ap[i].lan <--> switch.ethg[i+1];
        }
        switch.ethg[0] <--> gateway.ethg;
}
