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
import java.util.StringTokenizer;

import javax.sdp.*;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.ice.Agent;

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
     * Configures <tt>localAgent</tt> the the remote peer streams, components,
     * and candidates specified in <tt>sdp</tt>
     *
     * @param localAgent the {@link Agent} that we'd like to configure.
     *
     * @param sdp the SDP string that the remote peer sent.
     *
     * @throws Exception for all sorts of reasons.
     */
    @SuppressWarnings("unchecked") // jain-sdp legacy code.
    public static void parseSDP(Agent localAgent, String sdp)
        throws Exception
    {
        SdpFactory factory = SdpFactory.getInstance();
        SessionDescription sdess = factory.createSessionDescription(sdp);

        for(IceMediaStream stream : localAgent.getStreams())
        {
            stream.setRemotePassword(sdess.getAttribute("ice-pwd"));
            stream.setRemoteUfrag(sdess.getAttribute("ice-ufrag"));
        }

        Connection globalConn = sdess.getConnection();
        String globalConnAddr = null;
        if(globalConn != null)
            globalConnAddr = globalConn.getAddress();

        Vector<MediaDescription> mdescs = sdess.getMediaDescriptions(true);

        for (MediaDescription desc : mdescs)
        {
            String streamName = desc.getMedia().getMediaType();

            IceMediaStream stream = localAgent.getStream(streamName);

            if(stream == null)
                continue;

            Vector<Attribute> attributes = desc.getAttributes(true);
            for( Attribute attribute : attributes)
            {
                if(!attribute.getName().equals(CandidateAttribute.NAME))
                    continue;

                parseCandidate(attribute, stream);
            }

            //set default candidates
            Connection streamConn = desc.getConnection();
            String streamConnAddr = null;
            if(streamConn != null)
                streamConnAddr = streamConn.getAddress();
            else
                streamConnAddr = globalConnAddr;

            int port = desc.getMedia().getMediaPort();

            TransportAddress defaultRtpAddress =
                new TransportAddress(streamConnAddr, port, Transport.UDP);

            int rtcpPort = port + 1;
            String rtcpAttributeValue = desc.getAttribute("rtcp");

            if (rtcpAttributeValue != null)
                rtcpPort = Integer.parseInt(rtcpAttributeValue);

            TransportAddress defaultRtcpAddress =
                new TransportAddress(streamConnAddr, rtcpPort, Transport.UDP);

            Component rtpComponent = stream.getComponent(Component.RTP);
            Component rtcpComponent = stream.getComponent(Component.RTCP);

            Candidate defaultRtpCandidate
                = rtpComponent.findRemoteCandidate(defaultRtpAddress);
            rtpComponent.setDefaultRemoteCandidate(defaultRtpCandidate);

            if(rtcpComponent != null)
            {
                Candidate defaultRtcpCandidate
                    = rtcpComponent.findRemoteCandidate(defaultRtcpAddress);
                rtcpComponent.setDefaultRemoteCandidate(defaultRtcpCandidate);
            }
        }
    }

    /**
     * Parses the <tt>attribute</tt>.
     *
     * @param attribute the attribute that we need to parse.
     * @param stream the {@link IceMediaStream} that the candidate is supposed
     * to belong to.
     *
     * @return a newly created {@link RemoteCandidate} matching the
     * content of the specified <tt>attribute</tt> or <tt>null</tt> if the
     * candidate belonged to a component we don't have.
     */
    private static RemoteCandidate parseCandidate(Attribute      attribute,
                                                  IceMediaStream stream)
    {
        String value = null;

        try{
            value = attribute.getValue();
        }catch (Throwable t){}//can't happen

        StringTokenizer tokenizer = new StringTokenizer(value);

        //XXX add exception handling.
        String foundation = tokenizer.nextToken();
        int componentID = Integer.parseInt( tokenizer.nextToken() );
        Transport transport = Transport.parse(tokenizer.nextToken());
        long priority = Long.parseLong(tokenizer.nextToken());
        String address = tokenizer.nextToken();
        int port = Integer.parseInt(tokenizer.nextToken());

        TransportAddress transAddr
            = new TransportAddress(address, port, transport);

        tokenizer.nextToken(); //skip the "typ" String
        CandidateType type = CandidateType.parse(tokenizer.nextToken());

        Component component = stream.getComponent(componentID);

        if(component == null)
            return null;

        // check if there's a related address property

        RemoteCandidate relatedCandidate = null;
        if (tokenizer.countTokens() >= 4)
        {
            tokenizer.nextToken(); // skip the raddr element
            String relatedAddr = tokenizer.nextToken();
            tokenizer.nextToken(); // skip the rport element
            int relatedPort = Integer.parseInt(tokenizer.nextToken());

            TransportAddress raddr = new TransportAddress(
                            relatedAddr, relatedPort, Transport.UDP);

            relatedCandidate = component.findRemoteCandidate(raddr);
        }

        RemoteCandidate cand = new RemoteCandidate(transAddr, component, type,
                        foundation, priority, relatedCandidate);

        component.addRemoteCandidate(cand);

        return cand;
    }



    /**
     * An implementation of the <tt>candidate</tt> SDP attribute.
     */
    private static class CandidateAttribute extends AttributeField
    {
        /**
         * The SDP name of candidate attributes.
         */
        public static final String NAME = "candidate";

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
            return NAME;
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
