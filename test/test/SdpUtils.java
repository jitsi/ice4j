/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package test;

import gov.nist.core.*;
import gov.nist.javax.sdp.fields.*;

import java.util.*;

import javax.sdp.*;

import org.ice4j.*;
import org.ice4j.ice.*;

/**
 * Utilities for manipulating SDP. The utilities This method <b>do not</b> try
 * to act smart and make a lot of assumptions (e.g. at least one media stream
 * with at least one component) that may not always be true in real life and
 * lead to exceptions. Therefore, make sure you reread the code if reusing it
 * in an application. It should be fine for the purposes of our ice4j examples
 * though.
 *
 * @author Emil Ivov
 */
public class SdpUtils
{
    /**
     * Creates a session description containing the streams from the specified
     * <tt>agent</tt> using dummy codecs.
     *
     * @param agent the {@link Agent} we'd like to generate.
     *
     * @return a {@link SessionDescription} representing <tt>agent</tt>'s
     * streams.
     *
     * @throws Throwable on rainy days
     */
    public static String createSDPDescription(Agent agent) throws Throwable
    {
        SdpFactory factory = SdpFactory.getInstance();
        SessionDescription sdess = factory.createSessionDescription();
        Vector<Attribute> sessionAttributes = new Vector<Attribute>();

        TransportAddress defaultAddress = agent.getStreams().get(0)
            .getComponent(Component.RTP).getDefaultCandidate()
                .getTransportAddress();

        String addrType = defaultAddress.isIPv6()
                                    ? Connection.IP6
                                    : Connection.IP4;

        //origin (use ip from the first component of the first stream)
        Origin o = factory.createOrigin("ice4j.org", 0, 0, "IN", addrType,
                        defaultAddress.getHostAddress());
        sdess.setOrigin(o);

        //connection  (again use ip from first stream's component)
        Connection c = factory.createConnection("IN", addrType,
                        defaultAddress.getHostAddress() );
        sdess.setConnection(c);

        //ice u-frag and password
        sessionAttributes.add(factory.createAttribute("ice-pwd",
                            agent.getLocalPassword()));
        sessionAttributes.add(factory.createAttribute("ice-ufrag",
                            agent.getLocalUfrag()));

        //m lines
        List<IceMediaStream> streams = agent.getStreams();
        Vector<MediaDescription> mDescs = new Vector<MediaDescription>(
                        agent.getStreamCount());
        for(IceMediaStream stream : streams)
        {
           TransportAddress streamDefaultAddr = stream.getComponent(
                  Component.RTP).getDefaultCandidate().getTransportAddress();
           MediaDescription mdesc = factory.createMediaDescription(
                           stream.getName(), streamDefaultAddr.getPort(),
                           1, SdpConstants.RTP_AVP, new int[]{0});

           Vector<Attribute> candidates = new Vector<Attribute>();
           for(Component component : stream.getComponents())
           {
               for(Candidate cand : component.getLocalCandidates())
               {
                   candidates.add(new CandidateAttribute(cand));
               }
           }

           mdesc.setAttributes(candidates);

           mDescs.add(mdesc);
        }

        sdess.setAttributes(sessionAttributes);
        sdess.setMediaDescriptions(mDescs);
        return sdess.toString();
    }

    /**
     * An implementation of the <tt>candidate</tt> SDP attribute.
     */
    private static class CandidateAttribute extends AttributeField
    {
        /**
         * This class's serial version uid.
         */
        private static final long serialVersionUID = 1L;

        /**
         * The Candidate that we will be encapsulating.
         */
        private final Candidate candidate;

        /**
         * Creates an attribute instance
         *
         * @param candidate the Candidate
         */
        public CandidateAttribute(Candidate candidate)
        {
            this.candidate = candidate;
        }
        /**
         * Returns the name of this attribute
         *
         * @return a String identity.
         */
        public String getName()
        {
            return "candidate";
        }

        /**
         * Does nothing .
         *
         * @param name  ignored.
         */
        public void setName(String name){}

        /**
         * Always returns <tt>true</tt> as this attribute always has a value.
         *
         * @return true if the attribute has a value.
         */
        public boolean hasValue()
        {
            return true;
        };

        /**
         * Returns the value of this attribute.
         *
         * @return the value
         */
        public String getValue()
        {
            StringBuffer buff= new StringBuffer();

            buff.append(candidate.getFoundation());
            buff.append(" ").append(
                            candidate.getParentComponent().getComponentID());
            buff.append(" ").append(candidate.getTransport());
            buff.append(" ").append(candidate.getPriority());
            buff.append(" ").append(
                            candidate.getTransportAddress().getHostAddress());
            buff.append(" ").append(
                            candidate.getTransportAddress().getPort());
            buff.append(" typ ").append(
                            candidate.getType());

            TransportAddress relAddr = candidate.getRelatedAddress();

            if(relAddr != null)
            {
                buff.append(" raddr ").append(relAddr.getHostAddress());
                buff.append(" rport ").append(relAddr.getPort());
            }

            return buff.toString();
        }

        /**
         * Parses the value of this attribute.
         *
         * @param value the - attribute value
         *
         * @throws SdpException if there's a problem with the <tt>value
         * String</tt>.
         */
        public void setValue(String value) throws SdpException
        {

        }

        /**
         * Returns the type character for the field.
         *
         * @return the type character for the field.
         */
        public char getTypeChar()
        {
            return 'a';
        }

        /**
         * Returns a reference to this attribute.
         *
         * @return a reference to this attribute.
         */
        public CandidateAttribute clone()
        {
            return this;
        }

        /**
         * Returns the string encoded version of this object
         *
         * @return  the string encoded version of this object
         */
         public String encode()
         {
             StringBuffer sbuff = new StringBuffer(ATTRIBUTE_FIELD);
             sbuff.append(getName()).append(Separators.COLON);
             sbuff.append(getValue());
             return sbuff.append(Separators.NEWLINE).toString();
         }
    }
}
