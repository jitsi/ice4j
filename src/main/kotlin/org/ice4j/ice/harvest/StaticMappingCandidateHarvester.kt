package org.ice4j.ice.harvest

import org.ice4j.TransportAddress

/**
 * Uses a predefined static mask in order to generate [TransportAddress]es. This harvester is meant for use in
 * situations where servers are deployed behind a NAT or in a DMZ with static port mapping.
 *
 * Every time the [.harvest] method is called, the mapping harvester will return a list of candidates that provide
 * masked alternatives for every host candidate in the component. Kind of like a STUN server.
 *
 * Example: You run this on a server with address 192.168.0.1, that is behind a NAT with public IP: 93.184.216.119.
 * You allocate a host candidate 192.168.0.1/UDP/5000. This harvester is going to then generate an address
 * 93.184.216.119/UDP/5000.
 *
 * This harvester is instant and does not introduce any harvesting latency.
 *
 * @author Emil Ivov
 */
class StaticMappingCandidateHarvester(
    /** The public address (aka mask) */
    override val mask: TransportAddress,
    /** The local address (aka face) */
    override val face: TransportAddress
) : MappingCandidateHarvester() {
    override fun toString() = "${javaClass.name}(face=$face, mask=$mask)"
}
