package org.mixim.examples.dymo;


import org.mixim.base.connectionManager.ConnectionManager;
import mixnet.modules.MixnetWorldUtility;
import inet.nodes.ethernet.EtherSwitch;


network Adhoc
{
    parameters:
        double playgroundSizeX @unit(m); // x size of the area the nodes are in (in meters)
        double playgroundSizeY @unit(m); // y size of the area the nodes are in (in meters)
        double playgroundSizeZ @unit(m); // z size of the area the nodes are in (in meters)
        double accessPoints;
        double hosts;

        @display("bgb=$playgroundSizeX,$playgroundSizeY,white,,;bgp=10,50");

    submodules:
        world: MixnetWorldUtility {
            parameters:
                playgroundSizeX = playgroundSizeX;
                playgroundSizeY = playgroundSizeY;
                playgroundSizeZ = playgroundSizeZ;
                @display("p=171,25");

        }
        connectionManager: ConnectionManager {
            parameters:
                @display("p=66,25");
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
    connections:
        for i=0..accessPoints-1 {
            ap[i].ethg <--> switch.ethg[i+1];
        }
        switch.ethg[0] <--> gateway.ethg;
}
