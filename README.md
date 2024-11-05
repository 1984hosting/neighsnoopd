TL:DR - Listens for ARP replies and adds neighbors to the neighbors table.

## Neighsnoopd

Neighsnoopd[1] is a daemon for network environments where Distributed IRB is used with EVPN (Ethernet Virtual Private Network) using the Linux kernel. It listens for ARP[3] (Address Resolution Protocol) replies and NA[4] (Neighbor Advertisements) on a bridge interface and learns the MAC+IP associations of hosts connected to the network. These learned associations are then used to populate the local Linux kernel's neighbor table, where a routing suite like FRR can pick up them up to advertise through EVPN.

It also sends gratuitous ARP/NS to neighbors to check on them periodically before they time out and go stale. This is to reduce the amount of unnecessary route events being advertised through the fabric.

### Problem Overview

In an  EVPN setup with distributed gateways, a network subnet is advertised from many routers. So if a host on one of the routers has not communicated with it’s locally connected router, that router will not have a neighbor entry in it’s cache and thus will not advertise a route to that host. In that case, since many routers are advertising the same network, an upstream router will pick a route based on load balancing configuration. In that case it is more likely than not going to be routed to the wrong router, so the ARP request/NS will come from a remote gateway (relative to host1) on the same VNI (in case of VXLAN) and be sent back to that remote gateway as Unicast and never reach or go through the local anycast gateway for that host and so; will not be learned.
This means that traffic will be directed through a VTEP which has nothing to do with that network host except forwarding traffic for the same VNI. The packet takes a suboptimal route.


                                                                          
                                Problem                                   
                                                                          
     All three switches could have an anycast gateway of 10.1.1.254/24    
                                                                          
                                                                          
            10.1.1.20                                                     
             ┌─────┐         ┌─────┐         ┌─────┐                      
             │     │         │     │         │     │                      
             │     │         │     │         │     │                      
             └─host1────────┐└─host2────────┐└─host3────────┐             
                │10.1.1.1/24│   │10.1.1.2/24│   │10.1.1.3/24│             
                │           │   │           │   │           │             
                │  VTEP1    │   │  VTEP2    │   │  VTEP3    │             
                │           │   │           │   │           │             
                └──l3switch1┘   └┬─l3switch2┘   └──l3switch3┘             
                      │   ▲      │      ▲                                 
                      3   │      2      │                                 
                      │   └──────┘      │                                 
                      │                 │                                 
                      └───────────┐     │                                 
                                  │     1                                 
                                  ▼     │                                 
                               ┌────────┴───┐                             
                               │            │                             
                               │            │                             
                               │  VTEP4     │                             
                               │            │                             
                               │            │                             
                               └─────router1┘                             
                                                                          
                                                                          
                      Ping to host1 might take this route                 
                      to host1.                                           
                      1) Since router1 doesn't know where                 
                      host1 is; it might pick VTEP2 at random             
                      2) VTEP2 sends an arp and learns the MAC+IP,        
                      sees that the MAC is externally learned             
                      in the FDB and sends it over to VTEP1               
                      3) Host1 uses the nearest                           
                      anycast gateway, which is VTEP1 and                 
                      VTEP1 takes the sortest path to router1             
                                                                          


### Solution

Neighsnoopd solves these issues by monitoring the bridge for ARP replies and NA’s. When it detects either, it captures the MAC and IP address of the responding host and adds this information to the local neighbor table. This allows:
* The local neighbor table to be updated with MAC+IP associations, even when ARP/ND replies do not arrive on the local SVI for a subnet..
* The zebra daemon in FRR to learn the local MAC/IP associations, enabling EVPN Type-2 MAC+IP advertisements.
* When MAC+IP advertisements are enabled, other VTEP’s will know about those MAC+IP associations, enabling them to suppress ARP through the network fabric.
                                                               
                  Traffic flow with neighsnoopd running                     
                                                                            
            10.1.1.20                                                       
             ┌─────┐         ┌─────┐         ┌─────┐                        
             │     │         │     │         │     │                        
             │     │         │     │         │     │                        
             └─host1────────┐└─host2────────┐└─host3────────┐               
                │10.1.1.1/24│   │10.1.1.2/24│   │10.1.1.3/24│               
                │           │   │           │   │           │               
                │  VTEP1    │   │  VTEP2    │   │  VTEP3    │               
                │           │   │           │   │           │               
                └──l3switch1┘   └──l3switch2┘   └──l3switch3┘               
                      │   ▲                                                 
                      2   │                                                 
                      │   └────────────┐                                    
                      │                │                                    
                      └───────────┐    │                                    
                                  │    │                                    
                                  ▼    1                                    
                               ┌───────┴────┐                               
                               │            │                               
                               │            │                               
                               │  VTEP4     │                               
                               │            │                               
                               │            │                               
                               └─────router1┘                               
                                                                            
             *) Neighsnoopd listens for ARP replies/NA                      
             *) Adds MAC+IP pairs to neighbor table                         
             *) FRR picks up the record and advertises MAC+IP pair          
             *) Neighsnoopd keeps MAC+IP records fresh                      
             1) VTEP4 knows where host1 is, sends packet straight to VTEP1  
             2) Host1 takes the shortest path back                          
                                                                            

---

1. https://github.com/1984hosting/neighsnoopd
2. RFC 7209
3. RFC 826
4. RFC 4861
5. https://frrouting.org
6. https://docs.frrouting.org/en/latest/zebra.html
7. RFC 9136


