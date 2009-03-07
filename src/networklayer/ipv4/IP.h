//
// Copyright (C) 2004 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_IP_H
#define __INET_IP_H

#include "QueueBase.h"
#include "InterfaceTableAccess.h"
#include "RoutingTableAccess.h"
#include "IRoutingTable.h"
#include "ICMPAccess.h"
#include "IPControlInfo.h"
#include "IPDatagram.h"
#include "IPFragBuf.h"
#include "ProtocolMap.h"


class ARPPacket;
class ICMPMessage;

// ICMP type 2, code 4: fragmentation needed, but don't-fragment bit set
const int ICMP_FRAGMENTATION_ERROR_CODE = 4;


/**
 * Implements the IP protocol.
 */
class INET_API IP : public QueueBase
{
  public:
    /**
     * Implements a Netfilter-like datagram hook
     */
    class Hook {
      public:
        enum Result {
          ACCEPT, /**< allow datagram to pass to next hook */
          DROP, /**< do not allow datagram to pass to next hook, delete it */
          QUEUE /**< queue datagram for later re-injection */
        };

        virtual ~Hook() {};

        /**
         * called before a packet arriving from the network is routed
         */
        virtual Result datagramPreRoutingHook(const IPDatagram* datagram, const InterfaceEntry* inIE, const IP* ipLayer) { return ACCEPT; }

        /**
         * called before a packet arriving from the network is delivered locally
         */
        virtual Result datagramLocalInHook(const IPDatagram* datagram, const InterfaceEntry* inIE, const IP* ipLayer) { return ACCEPT; }

        /**
         * called before a packet arriving from the network is delivered via the network
         */
        virtual Result datagramForwardHook(const IPDatagram* datagram, const InterfaceEntry* inIE, const InterfaceEntry* outIE, const IPAddress& nextHopAddr, const IP* ipLayer) { return ACCEPT; }

        /**
         * called before a packet is delivered via the network
         */
        virtual Result datagramPostRoutingHook(const IPDatagram* datagram, const InterfaceEntry* inIE, const InterfaceEntry* outIE, const IPAddress& nextHopAddr, const IP* ipLayer) { return ACCEPT; }

        /**
         * called before a packet arriving locally is delivered
         */
        virtual Result datagramLocalOutHook(const IPDatagram* datagram, const InterfaceEntry* outIE, const IP* ipLayer) { return ACCEPT; }
    };

    /**
     * Represents an IPDatagram, queued by a Hook
     */
    class QueuedDatagramForHook {
      public:
        enum Hook {
          PREROUTING,
          LOCALIN, 
          FORWARD, 
          POSTROUTING,
          LOCALOUT
        };

        QueuedDatagramForHook(IPDatagram* datagram, InterfaceEntry* outIE, Hook hook) : datagram(datagram), outIE(outIE), hook(hook) {}
        virtual ~QueuedDatagramForHook() {}

        IPDatagram* datagram;
        InterfaceEntry* outIE;
        const Hook hook;
    };
  protected:
    IRoutingTable *rt;
    IInterfaceTable *ift;
    ICMPAccess icmpAccess;
    cGate *queueOutGate; // the most frequently used output gate

    // config
    int defaultTimeToLive;
    int defaultMCTimeToLive;
    simtime_t fragmentTimeoutTime;

    // working vars
    long curFragmentId; // counter, used to assign unique fragmentIds to datagrams
    IPFragBuf fragbuf;  // fragmentation reassembly buffer
    simtime_t lastCheckTime; // when fragbuf was last checked for state fragments
    ProtocolMapping mapping; // where to send packets after decapsulation

    // statistics
    int numMulticast;
    int numLocalDeliver;
    int numDropped;
    int numUnroutable;
    int numForwarded;

    // hooks
    std::multimap<int, Hook*> hooks;
    std::list<QueuedDatagramForHook> queuedDatagramsForHooks;

  protected:
    // utility: look up interface from getArrivalGate()
    virtual InterfaceEntry *getSourceInterfaceFrom(cPacket *msg);

    // utility: show current statistics above the icon
    virtual void updateDisplayString();

    /**
     * Encapsulate packet coming from higher layers into IPDatagram, using
     * the control info attached to the packet.
     */
    virtual IPDatagram *encapsulate(cPacket *transportPacket, InterfaceEntry *&destIE);

    /**
     * Encapsulate packet coming from higher layers into IPDatagram, using
     * the given control info. Override if you subclassed controlInfo and/or
     * want to add options etc to the datagram.
     */
    virtual IPDatagram *encapsulate(cPacket *transportPacket, InterfaceEntry *&destIE, IPControlInfo *controlInfo);

    /**
     * Creates a blank IP datagram. Override when subclassing IPDatagram is needed
     */
    virtual IPDatagram *createIPDatagram(const char *name);

    /**
     * Handle IPDatagram messages arriving from lower layer.
     * Decrements TTL, then invokes routePacket().
     */
    virtual void handlePacketFromNetwork(IPDatagram *datagram);

    /**
     * Handle messages (typically packets to be send in IP) from transport or ICMP.
     * Invokes encapsulate(), then routePacket().
     */
    virtual void handleMessageFromHL(cPacket *msg);

    /**
     * Routes and sends datagram received from higher layers.
     * Invokes datagramLocalOutHook(), then routePacket().
     */
    virtual void datagramLocalOut(IPDatagram* datagram, InterfaceEntry* destIE);

    /**
     * Handle incoming ARP packets by sending them over "queueOut" to ARP.
     */
    virtual void handleARP(ARPPacket *msg);

    /**
     * Handle incoming ICMP messages.
     */
    virtual void handleReceivedICMP(ICMPMessage *msg);

    /**
     * Performs routing. Based on the routing decision, it dispatches to
     * reassembleAndDeliver() for local packets, to fragmentAndSend() for forwarded packets,
     * to handleMulticastPacket() for multicast packets, or drops the packet if
     * it's unroutable or forwarding is off.
     */
    virtual void routePacket(IPDatagram *datagram, InterfaceEntry *destIE, bool fromHL);

    /**
     * Forwards packets to all multicast destinations, using fragmentAndSend().
     */
    virtual void routeMulticastPacket(IPDatagram *datagram, InterfaceEntry *destIE, InterfaceEntry *fromIE);

    /**
     * Perform reassembly of fragmented datagrams, then send them up to the
     * higher layers using sendToHL().
     */
    virtual void reassembleAndDeliver(IPDatagram *datagram);

    /**
     * Decapsulate and return encapsulated packet after attaching IPControlInfo.
     */
    virtual cPacket *decapsulateIP(IPDatagram *datagram);

    /**
     * Fragment packet if needed, then send it to the selected interface using
     * sendDatagramToOutput().
     */
    virtual void fragmentAndSend(IPDatagram *datagram, InterfaceEntry *ie, IPAddress nextHopAddr);

    /**
     * Last TTL check, then send datagram on the given interface.
     */
    virtual void sendDatagramToOutput(IPDatagram *datagram, InterfaceEntry *ie, IPAddress nextHopAddr);

    /**
     * called before a packet arriving from the network is routed
     */
    Hook::Result datagramPreRoutingHook(const IPDatagram* datagram, const InterfaceEntry* inIE);

    /**
     * called before a packet arriving from the network is delivered locally
     */
    Hook::Result datagramLocalInHook(const IPDatagram* datagram, const InterfaceEntry* inIE);

    /**
     * called before a packet arriving from the network is delivered via the network
     */
    Hook::Result datagramForwardHook(const IPDatagram* datagram, const InterfaceEntry* inIE, const InterfaceEntry* outIE, const IPAddress& nextHopAddr);

    /**
     * called before a packet is delivered via the network
     */
    Hook::Result datagramPostRoutingHook(const IPDatagram* datagram, const InterfaceEntry* inIE, const InterfaceEntry* outIE, const IPAddress& nextHopAddr);

    /**
     * called before a packet arriving locally is delivered
     */
    Hook::Result datagramLocalOutHook(IPDatagram* datagram, InterfaceEntry* outIE); 

  public:
    IP() {}

    /**
     * registers a Hook to be executed during datagram processing 
     */
    void registerHook(int priority, IP::Hook* hook);

    /**
     * unregisters a Hook to be executed during datagram processing 
     */
    void unregisterHook(int priority, IP::Hook* hook);

    /**
     * re-injects a previously queued datagram 
     */
    void reinjectDatagram(const IPDatagram* datagram, IP::Hook::Result verdict);

  protected:
    /**
     * Initialization
     */
    virtual void initialize();

    /**
     * Clean-up
     */
    virtual void finish();

    /**
     * Processing of IP datagrams. Called when a datagram reaches the front
     * of the queue.
     */
    virtual void endService(cPacket *msg);
};

#endif

