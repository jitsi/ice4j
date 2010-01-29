/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package org.ice4j;

/**
 * The class is used to represent an [address]:[port] couple where the Stun4J
 * stack is to listen for incoming messages. We need such a class so that we
 * could identify and manage (add, remove, etc.) DatagramListeners.
 *
 * @author Emil Ivov
 */

public class NetAccessPointDescriptor
{

    /**
     * The address string representing the host (interface) where the stack
     * should bind.
     */
    protected TransportAddress stunAddr = null;


    /**
     * Creates a net access point that will bind to the  specified address.
     *
     * @param address a valid Stun Address.
     */
    public NetAccessPointDescriptor(TransportAddress address)
    {
        stunAddr = address;
    }

    /**
     * Attempts to automatically detect the address of local host and binds
     * on the specified port.
     *
     * @param port the port where to bind.
     */
/*    public NetAccessPointDescriptor(int port)
    {
        stunAddr = new StunAddress(port);
    }
 */

    /**
     * Compares this object against the specified object. The result is true if
     * and only if the argument is not null and it represents the same address
     * as this object.
     *
     * Two instances of InetSocketAddress represent the same address if both the
     * InetAddresses (or hostnames if it is unresolved) and port numbers are
     * equal. If both addresses are unresolved, then the hostname & the port
     * number are compared.
     *
     * @param obj the object to compare against.
     * @return true if the objects are the same; false otherwise.
     */
    public final boolean equals(Object obj)
    {
        if(obj == null
           || !(obj instanceof NetAccessPointDescriptor))
           return false;

        if (obj == this)
            return true;

        return stunAddr.equals( ((NetAccessPointDescriptor)obj).stunAddr );
    }

    /**
     * Returns the socket address wrapped by this class.
     * @return an InetSocketAddress instance.
     */
    public TransportAddress getAddress()
    {
        return stunAddr;
    }

    /**
     * Clones the NetAccessPointDescriptor.
     *
     * @return a copy of this NetAccessPointDescriptor.
     */
    public Object clone()
    {
        NetAccessPointDescriptor napd = new NetAccessPointDescriptor(stunAddr);

        return napd;
    }


    /**
     * Returns the hashcode of this NetAccessPointDescriptor so that it could
     * be used as a key in hashtables.
     *
     * @return the hashcode of this NetAccessPointDescriptor
     */
    public int hashCode(){
        //we could actually simply return the hashcode of the socket address
        //since it identifies us more or less uniquely
        return stunAddr.getSocketAddress().hashCode();
    }

    /**
     * Returns a string representation of this NetAccessPointDescriptor.
     *
     * @return  a string representation of the object.
     */
    public String toString()
    {

        return "StunAddress=" + ( (stunAddr==null)? "null":stunAddr.toString());
    }
}
