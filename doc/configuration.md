# General
This file describes some of the java properties which ```ice4j``` uses
to configure itself.

## Interfaces and IP addresses

### ```org.ice4j.ice.harvest.ALLOWED_INTERFACES```
Default: all interfaces are allowed.

This property can be used to specify a ";"-separated list of interfaces which are
allowed to be used for candidate allocations. If not specified, all interfaces are
considered allowed, unless they are explicitly blocked (see below).

### ```org.ice4j.ice.harvest.BLOCKED_INTERFACES```
Default: no interfaces are blocked.

This property can be used to specify a ";"-separated list of interfaces which are
not allowed to be used for candidate allocations. 

### ```org.ice4j.ice.harvest.ALLOWED_ADDRESSES```
Default: all addresses are allowed.

This property can be used to specify a ";"-separated list of IP addresses which
are allowed to be used for candidate allocations. If not specified, all addresses
are considered allowed, unless they are explicitly blocked (see below).

### ```org.ice4j.ice.harvest.BLOCKED_ADDRESSES```
Default: no addresses are blocked.

This property can be used to specify a ";"-separated list of IP addresses which
are not allowed to be used for candidate allocations. 

### ```org.ice4j.ipv6.DISABLED```
Type: boolean

Default: false

This property can be used to disable binding on IPv6 addresses.


## Mapping harvesters
Ice4j uses the concept of "mapping harvesters" to handle known IP address
mappings. A set of mapping harvesters is configured once when the library
initializes, and each of them contains a pair of IP addresses (local and public).

When an ICE Agent gathers candidates, it uses the set of mapping harvesters
to obtain ```srflx``` candidates without the use to e.g. a STUN server dynamically.

Mapping harvesters preserve the port number of the original candidate, so they should
only be used when port numbers are preserved.

Ice4j implements three types of mapping harvesters: one with a pre-configured pair of 
addresses, one two which discover addresses dynamically using the AWS API and STUN.


### ```org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS```
### ```org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS```
Default: none

Configures the addresses of the pre-configured mapping harvester.

### ```org.ice4j.ice.harvest.DISABLE_AWS_HARVESTER```
Default: false

Explicitly disables the AWS mapping harvester. By default the harvester
is enabled if ice4j detects that it is running in the AWS network.

### ```org.ice4j.ice.harvest.FORCE_AWS_HARVESTER```
Default: false

Force the use of the AWS mapping harvester, even if ice4j did not detect
that it is running in the AWS network.

### ```org.ice4j.ice.harvest.STUN_MAPPING_HARVESTER_ADDRESSES```
Default: none

A comma-separated list of STUN server addresses to use for mapping harvesters.
Each STUN server address is an ip_address:port pair.
Example: ```stun1.example.com:12345,stun2.example.com:23456```

## Single port UDP harvester
### ```org.ice4j.ice.harvest.AbstractUdpHarvester.SO_RCVBUF```
Configures the receive buffer size for the single port UDP harvester
(or other AbstractUdpListener implementations). If this is not set
the system default value will be used (the ```net.core.rmem_default```
sysctl parameter on linux). Note that the system maximum value may need to
be increased (```net.core.rmem_max``` on linux).
