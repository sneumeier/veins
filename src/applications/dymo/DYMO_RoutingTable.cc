/*
 *  Copyright (C) 2005 Mohamed Louizi
 *  Copyright (C) 2006,2007 Christoph Sommer <christoph.sommer@informatik.uni-erlangen.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdexcept>
#include <sstream>
#include <algorithm>
#include "applications/dymo/DYMO_RoutingTable.h"
#include "IPAddressResolver.h"
#include "IPv4InterfaceData.h"

DYMO_RoutingTable::DYMO_RoutingTable(cModule* host, const IPAddress& myAddr, const char* DYMO_INTERFACES, const IPAddress& LL_MANET_ROUTERS) {
	// get our host module
	if (!host) throw std::runtime_error("No parent module found");

	// get our routing table
	routingTable = IPAddressResolver().routingTableOf(host);
	if (!routingTable) throw std::runtime_error("No routing table found");

	// get our interface table
	IInterfaceTable *ift = IPAddressResolver().interfaceTableOf(host);
	if (!ift) throw std::runtime_error("No interface table found");

	// look at all interface table entries
	cStringTokenizer interfaceTokenizer(DYMO_INTERFACES);
	const char *ifname;
	while ((ifname = interfaceTokenizer.nextToken()) != NULL) {
		InterfaceEntry* ie = ift->getInterfaceByName(ifname);
		if (!ie) throw std::runtime_error("No such interface");

		// assign IP Address to all connected interfaces
		if (!ie->isLoopback()) {
			ie->ipv4Data()->setIPAddress(myAddr);
			ie->ipv4Data()->setNetmask(IPAddress::ALLONES_ADDRESS); // set to ALLONES_ADDRESS to avoid auto-generation of routes

			// associate interface with default and LL_MANET_ROUTERS multicast groups
    			IPv4InterfaceData::IPAddressVector mcg = ie->ipv4Data()->getMulticastGroups();
			if (std::find(mcg.begin(), mcg.end(), IPAddress::ALL_HOSTS_MCAST) == mcg.end()) mcg.push_back(IPAddress::ALL_HOSTS_MCAST);
			if (std::find(mcg.begin(), mcg.end(), IPAddress::ALL_ROUTERS_MCAST) == mcg.end()) mcg.push_back(IPAddress::ALL_ROUTERS_MCAST);
			if (std::find(mcg.begin(), mcg.end(), LL_MANET_ROUTERS) == mcg.end()) mcg.push_back(LL_MANET_ROUTERS);
			ie->ipv4Data()->setMulticastGroups(mcg);

			ie->setBroadcast(true);
		}

		// add interface to LL_MANET_ROUTERS multicast group
		IPRoute* re = new IPRoute(); //TODO: add @c delete to destructor
		re->setHost(LL_MANET_ROUTERS);
		re->setNetmask(IPAddress::ALLONES_ADDRESS); // TODO: can't set this to none?
		re->setGateway(IPAddress()); // none
		re->setInterface(ie);
		re->setType(IPRoute::DIRECT);
		re->setSource(IPRoute::BGP); // TODO: add source type "DYMO" to IRoutingTable.h?
		re->setMetric(1);
		routingTable->addRoute(re);

		//TODO: register to receive ICMP messages, maybe by redirecting networkLayer.icmp.errorOut?

	}
}

DYMO_RoutingTable::~DYMO_RoutingTable() {
	DYMO_RoutingEntry* entry;
	while ((entry = getRoute(0))) deleteRoute(entry);
}

const char* DYMO_RoutingTable::getFullName() const {
	return "DYMO_RoutingTable";
}

std::string DYMO_RoutingTable::info() const {
	std::ostringstream ss;

	ss << getNumRoutes() << " entries";

	int broken = 0;
	for (std::vector<DYMO_RoutingEntry *>::const_iterator iter = routeVector.begin(); iter < routeVector.end(); iter++) {
		DYMO_RoutingEntry* e = *iter;
		if (e->routeBroken) broken++;
	}
	ss << " (" << broken << " broken)";

	ss << " {" << std::endl;
	for (std::vector<DYMO_RoutingEntry *>::const_iterator iter = routeVector.begin(); iter < routeVector.end(); iter++) {
		DYMO_RoutingEntry* e = *iter;
		ss << "  " << *e << std::endl;
	}
	ss << "}";

	return ss.str();
}

std::string DYMO_RoutingTable::detailedInfo() const {
	return info();
}

//=================================================================================================
/*
 * Function returns the size of the table
 */ 
//=================================================================================================
int DYMO_RoutingTable::getNumRoutes() const {
  return (int)routeVector.size(); 
}

//=================================================================================================
/*
 * Function gets an routing entry at the given position 
 */ 
//=================================================================================================
DYMO_RoutingEntry* DYMO_RoutingTable::getRoute(int k){
  if(k < (int)routeVector.size())
    return routeVector[k];
  else
    return NULL;
}

//=================================================================================================
/*
 * 
 */ 
//=================================================================================================
void DYMO_RoutingTable::addRoute(DYMO_RoutingEntry *entry){
	routeVector.push_back(entry);
}

//=================================================================================================
/*
 */ 
//=================================================================================================
void DYMO_RoutingTable::deleteRoute(DYMO_RoutingEntry *entry){

	// update standard routingTable
	if (entry->routingEntry) {
		routingTable->deleteRoute(entry->routingEntry);
		entry->routingEntry = 0;
	}

	// update DYMO routingTable
	std::vector<DYMO_RoutingEntry *>::iterator iter;
	for(iter = routeVector.begin(); iter < routeVector.end(); iter++){
		if(entry == *iter){
			routeVector.erase(iter);
			//updateDisplayString();
			delete entry;
			return;
		}
	}

	throw std::runtime_error("unknown routing entry requested to be deleted");
}

//=================================================================================================
/*
 */ 
//=================================================================================================
void DYMO_RoutingTable::maintainAssociatedRoutingTable() {
	std::vector<DYMO_RoutingEntry *>::iterator iter;
	for(iter = routeVector.begin(); iter < routeVector.end(); iter++){
		maintainAssociatedRoutingEntryFor(*iter);
	}
}

//=================================================================================================
/*
 */ 
//=================================================================================================
DYMO_RoutingEntry* DYMO_RoutingTable::getByAddress(IPAddress addr){

	std::vector<DYMO_RoutingEntry *>::iterator iter;
  
	for(iter = routeVector.begin(); iter < routeVector.end(); iter++){
		DYMO_RoutingEntry *entry = *iter;
    
		if(entry->routeAddress == addr){
			return entry;
		}
	}
  
	return 0;
}

//=================================================================================================
/*
 */ 
//=================================================================================================
DYMO_RoutingEntry* DYMO_RoutingTable::getForAddress(IPAddress addr) {
	std::vector<DYMO_RoutingEntry *>::iterator iter;

	int longestPrefix = 0; 
	DYMO_RoutingEntry* longestPrefixEntry = 0;
	for(iter = routeVector.begin(); iter < routeVector.end(); iter++) {
		DYMO_RoutingEntry *entry = *iter;

		// skip if we already have a more specific match
		if (!(entry->routePrefix > longestPrefix)) continue;

		// skip if address is not in routeAddress/routePrefix block
		if (!addr.prefixMatches(entry->routeAddress, entry->routePrefix)) continue;

		// we have a match
		longestPrefix = entry->routePrefix;
		longestPrefixEntry = entry;
	}

	return longestPrefixEntry;
}

//=================================================================================================
/*
 */ 
//=================================================================================================
DYMO_RoutingTable::RouteVector DYMO_RoutingTable::getRoutingTable(){
	return routeVector;
}

void DYMO_RoutingTable::maintainAssociatedRoutingEntryFor(DYMO_RoutingEntry* entry){
	if (!entry->routeBroken) {
		// entry is valid
		if (!entry->routingEntry) {
			// entry does not yet have an associated routing entry. Add one.
			IPRoute* re = new IPRoute();
			re->setHost(entry->routeAddress);
			re->setNetmask(IPAddress::ALLONES_ADDRESS);
			re->setGateway(entry->routeNextHopAddress);
			re->setInterface(entry->routeNextHopInterface);
			re->setType((entry->routeDist > 1) ? IPRoute::REMOTE : IPRoute::DIRECT);
			re->setSource(IPRoute::BGP); // TODO: add source type "DYMO" to IRoutingTable.h?
			re->setMetric(1);
			entry->routingEntry = re;
			routingTable->addRoute(re);
		} else {
			// entry already has an associated routing entry. Update it.
			IPRoute* re = entry->routingEntry;
			re->setHost(entry->routeAddress);
			re->setNetmask(IPAddress::ALLONES_ADDRESS);
			re->setGateway(entry->routeNextHopAddress);
			re->setInterface(entry->routeNextHopInterface);
			re->setType((entry->routeDist > 1) ? IPRoute::REMOTE : IPRoute::DIRECT);
			re->setSource(IPRoute::BGP); // TODO: add source type "DYMO" to IRoutingTable.h?
			re->setMetric(1);
		}
	} else {
		// entry is invalid
		if (entry->routingEntry) {
			// entry still has an associated routing entry. Delete it.
			routingTable->deleteRoute(entry->routingEntry);
			entry->routingEntry = 0;
		} else {
			// entry does no longer have an assoicated routing entry. Do nothing.
		}
	}
}

std::ostream& operator<<(std::ostream& os, const DYMO_RoutingTable& o)
{
	os << o.info();
	return os;
}

