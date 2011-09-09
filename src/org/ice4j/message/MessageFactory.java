/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.message;

import java.io.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;

/**
 * This class provides factory methods to allow an application to create STUN
 * Messages from a particular implementation.
 *
 * @author Emil Ivov
 * @author Sebastien Vincent
 * @author Lubomir Marinov
 */
public class MessageFactory
{

    /**
     * The <tt>Logger</tt> used by the <tt>MessageFactory</tt> class and its
     * instances.
     */
    private static final Logger logger
        = Logger.getLogger(MessageFactory.class.getName());

    /**
     * Creates a default binding request. The request DOES NOT contains a
     * ChangeRequest attribute with zero change ip and change port flags.
     *
     * @return a default binding request.
     */
    public static Request createBindingRequest()
    {
        Request bindingRequest = new Request();
        try
        {
            bindingRequest.setMessageType(Message.BINDING_REQUEST);
        } catch (IllegalArgumentException ex)
        {
            // there should be no exc here since we're the creators.
            logger.log(Level.FINE, "Failed to set message type.", ex);
        }

        /* do not add this by default */
        /*
         * //add a change request attribute ChangeRequestAttribute attribute =
         * AttributeFactory.createChangeRequestAttribute();
         *
         * try { bindingRequest.addAttribute(attribute); } catch (StunException
         * ex) { //shouldn't happen throw new
         * RuntimeException("Failed to add a change request "
         * +"attribute to a binding request!"); }
         */
        return bindingRequest;
    }

    /**
     * Creates a default binding request. The request contains a ChangeReqeust
     * attribute with zero change ip and change port flags. It also contains the
     * PRIORITY attribute used for ICE processing
     *
     * @param priority the value for the priority attribute
     * @return a BindingRequest header with ICE PRIORITY attribute
     * @throws StunException if we have a problem creating the request
     */
    public static Request createBindingRequest(long priority)
                    throws StunException
    {
        Request bindingRequest = createBindingRequest();

        PriorityAttribute attribute = AttributeFactory
                        .createPriorityAttribute(priority);
        bindingRequest.addAttribute(attribute);

        return bindingRequest;
    }

    /**
     * Creates a default binding request. The request contains a ChangeReqeust
     * attribute with zero change ip and change port flags. It contains the
     * PRIORITY, ICE-CONTROLLED or ICE-CONTROLLING attributes used for ICE
     * processing
     *
     * @param priority the value of the ICE priority attributes
     * @param controlling the value of the controlling attribute
     * @param tieBreaker the value of the ICE tie breaker attribute
     * @return a BindingRequest header with some ICE attributes (PRIORITY,
     * ICE-CONTROLLING / ICE-CONTROLLED)
     * @throws StunException if we have a problem creating the request
     */
    public static Request createBindingRequest(long priority,
                    boolean controlling, long tieBreaker)
                    throws StunException
    {
        Request bindingRequest = createBindingRequest();

        PriorityAttribute attribute = AttributeFactory
                        .createPriorityAttribute(priority);
        bindingRequest.addAttribute(attribute);

        if (controlling)
        {
            IceControllingAttribute iceControllingAttribute = AttributeFactory
                            .createIceControllingAttribute(tieBreaker);
            bindingRequest.addAttribute(iceControllingAttribute);
        } else
        {
            IceControlledAttribute iceControlledAttribute = AttributeFactory
                            .createIceControlledAttribute(tieBreaker);
            bindingRequest.addAttribute(iceControlledAttribute);
        }

        return bindingRequest;
    }

    /**
     * Creates a BindingResponse in a 3489 compliant manner, assigning the
     * specified values to mandatory headers.
     *
     * @param mappedAddress the address to assign the mappedAddressAttribute
     * @param sourceAddress the address to assign the sourceAddressAttribute
     * @param changedAddress the address to assign the changedAddressAttribute
     * @return a BindingResponse assigning the specified values to mandatory
     * headers.
     * @throws IllegalArgumentException if there was something wrong with the
     * way we are trying to create the response.
     */
    public static Response create3489BindingResponse(
                    TransportAddress mappedAddress,
                    TransportAddress sourceAddress,
                    TransportAddress changedAddress)
                    throws IllegalArgumentException
    {
        Response bindingResponse = new Response();
        bindingResponse.setMessageType(Message.BINDING_SUCCESS_RESPONSE);

        // mapped address
        MappedAddressAttribute mappedAddressAttribute = AttributeFactory
                        .createMappedAddressAttribute(mappedAddress);

        // the changed address and source address attribute were removed in
        // RFC 5389 so we should be prepared to go without them.

        // source address
        SourceAddressAttribute sourceAddressAttribute = null;

        if (sourceAddress != null)
            sourceAddressAttribute = AttributeFactory
                            .createSourceAddressAttribute(sourceAddress);

        // changed address
        ChangedAddressAttribute changedAddressAttribute = null;

        if (changedAddress != null)
            changedAddressAttribute = AttributeFactory
                            .createChangedAddressAttribute(changedAddress);

        bindingResponse.addAttribute(mappedAddressAttribute);

        // the changed address and source address attribute were removed in
        // RFC 5389 so we should be prepared to go without them.

        if (sourceAddressAttribute != null)
            bindingResponse.addAttribute(sourceAddressAttribute);

        if (changedAddressAttribute != null)
            bindingResponse.addAttribute(changedAddressAttribute);

        return bindingResponse;
    }

    /**
     * Creates a BindingResponse in a 5389 compliant manner containing a single
     * <tt>XOR-MAPPED-ADDRESS</tt> attribute
     *
     * @param request the request that created the transaction that this
     * response will belong to.
     * @param mappedAddress the address to assign the mappedAddressAttribute
     * @return a BindingResponse assigning the specified values to mandatory
     * headers.
     * @throws IllegalArgumentException if there was something wrong with the
     * way we are trying to create the response.
     */
    public static Response createBindingResponse(Request request,
                    TransportAddress mappedAddress)
                    throws IllegalArgumentException
    {
        Response bindingResponse = new Response();
        bindingResponse.setMessageType(Message.BINDING_SUCCESS_RESPONSE);

        // xor mapped address
        XorMappedAddressAttribute xorMappedAddressAttribute = AttributeFactory
                        .createXorMappedAddressAttribute(mappedAddress,
                                        request.getTransactionID());

        bindingResponse.addAttribute(xorMappedAddressAttribute);

        return bindingResponse;
    }

    /**
     * Creates a binding error response according to the specified error code
     * and unknown attributes.
     *
     * @param errorCode the error code to encapsulate in this message
     * @param reasonPhrase a human readable description of the error
     * @param unknownAttributes a char[] array containing the ids of one or more
     * attributes that had not been recognized.
     * @throws IllegalArgumentException INVALID_ARGUMENTS if one or more of the
     * given parameters had an invalid value.
     *
     * @return a binding error response message containing an error code and a
     * UNKNOWN-ATTRIBUTES header
     */
    public static Response createBindingErrorResponse(char errorCode,
                    String reasonPhrase, char[] unknownAttributes)
        throws IllegalArgumentException
    {
        Response bindingErrorResponse = new Response();
        bindingErrorResponse.setMessageType(Message.BINDING_ERROR_RESPONSE);

        // init attributes
        UnknownAttributesAttribute unknownAttributesAttribute = null;
        ErrorCodeAttribute errorCodeAttribute = AttributeFactory
                        .createErrorCodeAttribute(errorCode,
                                        reasonPhrase);

        bindingErrorResponse.addAttribute(errorCodeAttribute);

        if (unknownAttributes != null)
        {
            unknownAttributesAttribute = AttributeFactory
                            .createUnknownAttributesAttribute();
            for (int i = 0; i < unknownAttributes.length; i++)
            {
                unknownAttributesAttribute
                                .addAttributeID(unknownAttributes[i]);
            }
            bindingErrorResponse
                            .addAttribute(unknownAttributesAttribute);
        }

        return bindingErrorResponse;
    }

    /**
     * Creates a binding error response with UNKNOWN_ATTRIBUTES error code and
     * the specified unknown attributes.
     *
     * @param unknownAttributes a char[] array containing the ids of one or more
     * attributes that had not been recognized.
     * @throws StunException INVALID_ARGUMENTS if one or more of the given
     * parameters had an invalid value.
     * @return a binding error response message containing an error code and a
     * UNKNOWN-ATTRIBUTES header
     */
    public static Response createBindingErrorResponseUnknownAttributes(
                    char[] unknownAttributes) throws StunException
    {
        return createBindingErrorResponse(
                        ErrorCodeAttribute.UNKNOWN_ATTRIBUTE, null,
                        unknownAttributes);
    }

    /**
     * Creates a binding error response with UNKNOWN_ATTRIBUTES error code and
     * the specified unknown attributes and reason phrase.
     *
     * @param reasonPhrase a short description of the error.
     * @param unknownAttributes a char[] array containing the ids of one or more
     * attributes that had not been recognized.
     * @throws StunException INVALID_ARGUMENTS if one or more of the given
     * parameters had an invalid value.
     * @return a binding error response message containing an error code and a
     * UNKNOWN-ATTRIBUTES header
     */
    public static Response createBindingErrorResponseUnknownAttributes(
                    String reasonPhrase, char[] unknownAttributes)
                    throws StunException
    {
        return createBindingErrorResponse(
                        ErrorCodeAttribute.UNKNOWN_ATTRIBUTE,
                        reasonPhrase, unknownAttributes);
    }

    /**
     * Creates a binding error response with an ERROR-CODE attribute.
     *
     * @param errorCode the error code to encapsulate in this message
     * @param reasonPhrase a human readable description of the error.
     *
     * @return a binding error response message containing an error code and a
     * UNKNOWN-ATTRIBUTES header
     */
    public static Response createBindingErrorResponse(char errorCode,
                    String reasonPhrase)
    {
        return createBindingErrorResponse(errorCode, reasonPhrase, null);
    }

    /**
     * Creates a binding error response according to the specified error code.
     *
     * @param errorCode the error code to encapsulate in this message attributes
     * that had not been recognized.
     *
     * @return a binding error response message containing an error code and a
     * UNKNOWN-ATTRIBUTES header
     */
    public static Response createBindingErrorResponse(char errorCode)
    {
        return createBindingErrorResponse(errorCode, null, null);
    }

    /**
     * Creates a default binding indication.
     *
     * @return a default binding indication.
     */
    public static Indication createBindingIndication()
    {
        Indication bindingIndication = new Indication();

        bindingIndication.setMessageType(Message.BINDING_INDICATION);
        return bindingIndication;
    }

    /**
     * Create an allocate request without attribute.
     *
     * @return an allocate request
     */
    public static Request createAllocateRequest()
    {
        Request allocateRequest = new Request();

        try
        {
            allocateRequest.setMessageType(Message.ALLOCATE_REQUEST);
        } catch (IllegalArgumentException ex)
        {
            // there should be no exc here since we're the creators.
            logger.log(Level.FINE, "Failed to set message type.", ex);
        }
        return allocateRequest;
    }

    /**
     * Create an allocate request to allocate an even port. Attention this does
     * not have attributes for long-term authentication.
     *
     * @param protocol requested protocol number
     * @param rFlag R flag for the EVEN-PORT
     * @return an allocation request
     */
    public static Request createAllocateRequest(byte protocol,
                    boolean rFlag)
    {
        Request allocateRequest = new Request();

        try
        {
            allocateRequest.setMessageType(Message.ALLOCATE_REQUEST);

            /* XXX add enum somewhere for transport number */
            if (protocol != 6 && protocol != 17)
                throw new StunException("Protocol not valid!");

            // REQUESTED-TRANSPORT
            allocateRequest.addAttribute(
                    AttributeFactory.createRequestedTransportAttribute(
                            protocol));

            // EVEN-PORT
            if (rFlag)
            {
                allocateRequest.addAttribute(
                        AttributeFactory.createEvenPortAttribute(rFlag));
            }
        }
        catch (StunException ex)
        {
            logger.log(Level.FINE, "Failed to set message type.", ex);
        }
        return allocateRequest;
    }

    /**
     * Create an allocate request for a Google TURN relay (old TURN protocol
     * modified).
     *
     * @param username short-term username
     * @return an allocation request
     */
    public static Request createGoogleAllocateRequest(String username)
    {
        Request allocateRequest = new Request();
        Attribute usernameAttr = AttributeFactory.createUsernameAttribute(
                username);
        Attribute magicCookieAttr =
            AttributeFactory.createMagicCookieAttribute();

        allocateRequest.setMessageType(Message.ALLOCATE_REQUEST);
        // first attribute is MAGIC-COOKIE
        allocateRequest.addAttribute(magicCookieAttr);
        allocateRequest.addAttribute(usernameAttr);

        return allocateRequest;
    }

    /**
     * Adds the <tt>Attribute</tt>s to a specific <tt>Request</tt> which support
     * the STUN long-term credential mechanism.
     * <p>
     * <b>Warning</b>: The MESSAGE-INTEGRITY <tt>Attribute</tt> will also be
     * added so <tt>Attribute</tt>s added afterwards will not be taken into
     * account for the calculation of the MESSAGE-INTEGRITY value. For example,
     * the FINGERPRINT <tt>Attribute</tt> may still safely be added afterwards,
     * because it is known to appear after the MESSAGE-INTEGRITY.
     * </p>
     *
     * @param request the <tt>Request</tt> in which the <tt>Attribute</tt>s of
     * the STUN long-term credential mechanism are to be added
     * @param username the value for the USERNAME <tt>Attribute</tt> to be added
     * to <tt>request</tt>
     * @param realm the value for the REALM <tt>Attribute</tt> to be added to
     * <tt>request</tt>
     * @param nonce the value for the NONCE <tt>Attribute</tt> to be added to
     * <tt>request</tt>
     *
     * @throws StunException if anything goes wrong while adding the
     * <tt>Attribute</tt>s to <tt>request</tt> which support the STUN long-term
     * credential mechanism
     */
    public static void addLongTermCredentialAttributes(
            Request request,
            byte username[], byte realm[], byte nonce[])
        throws StunException
    {
        UsernameAttribute usernameAttribute
            = AttributeFactory.createUsernameAttribute(username);
        RealmAttribute realmAttribute
            = AttributeFactory.createRealmAttribute(realm);
        NonceAttribute nonceAttribute
            = AttributeFactory.createNonceAttribute(nonce);

        request.addAttribute(usernameAttribute);
        request.addAttribute(realmAttribute);
        request.addAttribute(nonceAttribute);

        // MESSAGE-INTEGRITY
        MessageIntegrityAttribute messageIntegrityAttribute;

        try
        {
            /*
             * The value of USERNAME is a variable-length value. It MUST contain
             * a UTF-8 [RFC3629] encoded sequence of less than 513 bytes, and
             * MUST have been processed using SASLprep [RFC4013].
             */
            messageIntegrityAttribute
                = AttributeFactory.createMessageIntegrityAttribute(
                        new String(username, "UTF-8"));
        }
        catch (UnsupportedEncodingException ueex)
        {
            throw new StunException("username", ueex);
        }
        request.addAttribute(messageIntegrityAttribute);
    }

    /**
     * Creates a new TURN Refresh <tt>Request</tt> without any optional
     * attributes such as LIFETIME.
     *
     * @return a new TURN Refresh <tt>Request</tt> without any optional
     * attributes such as LIFETIME
     */
    public static Request createRefreshRequest()
    {
        Request refreshRequest = new Request();

        try
        {
            refreshRequest.setMessageType(Message.REFRESH_REQUEST);
        }
        catch (IllegalArgumentException iaex)
        {
            /*
             * We don't actually expect the exception to happen so we're
             * ignoring it.
             */
            logger.log(Level.FINE, "Failed to set message type.", iaex);
        }
        return refreshRequest;
    }

    /**
     * Create a refresh request.
     *
     * @param lifetime lifetime value
     * @return refresh request
     */
    public static Request createRefreshRequest(int lifetime)
    {
        Request refreshRequest = new Request();

        try
        {
            refreshRequest.setMessageType(Message.REFRESH_REQUEST);

            /* add a LIFETIME attribute */
            LifetimeAttribute lifetimeReq = AttributeFactory
                            .createLifetimeAttribute(lifetime);
            refreshRequest.addAttribute(lifetimeReq);
        } catch (IllegalArgumentException ex)
        {
            logger.log(Level.FINE, "Failed to set message type.", ex);
        }

        return refreshRequest;
    }

    /**
     * Create a ChannelBind request.
     *
     * @param channelNumber the channel number
     * @param peerAddress the peer address
     * @param tranID the ID of the transaction that we should be using
     *
     * @return channel bind request
     */
    public static Request createChannelBindRequest(char channelNumber,
                    TransportAddress peerAddress, byte[] tranID)
    {
        Request channelBindRequest = new Request();

        try
        {
            channelBindRequest
                            .setMessageType(Message.CHANNELBIND_REQUEST);

            // add a CHANNEL-NUMBER attribute
            ChannelNumberAttribute channelNumberAttribute = AttributeFactory
                            .createChannelNumberAttribute(channelNumber);
            channelBindRequest.addAttribute(channelNumberAttribute);

            // add a XOR-PEER-ADDRESS
            XorPeerAddressAttribute peerAddressAttribute = AttributeFactory
                            .createXorPeerAddressAttribute(peerAddress,
                                            tranID);

            channelBindRequest.addAttribute(peerAddressAttribute);
        } catch (IllegalArgumentException ex)
        {
            logger.log(Level.FINE, "Failed to set message type.", ex);
        }

        return channelBindRequest;
    }

    /**
     * Creates a new TURN CreatePermission <tt>Request</tt> with a specific
     * value for its XOR-PEER-ADDRESS attribute.
     *
     * @param peerAddress the value to assigned to the XOR-PEER-ADDRESS
     * attribute
     * @param transactionID the ID of the transaction which is to be used for
     * the assignment of <tt>peerAddress</tt> to the XOR-PEER-ADDRESS attribute
     * @return a new TURN CreatePermission <tt>Request</tt> with the specified
     * value for its XOR-PEER-ADDRESS attribute
     */
    public static Request createCreatePermissionRequest(
            TransportAddress peerAddress,
            byte[] transactionID)
    {
        Request createPermissionRequest = new Request();

        try
        {
            createPermissionRequest.setMessageType(
                    Message.CREATEPERMISSION_REQUEST);
        }
        catch (IllegalArgumentException iaex)
        {
            // Expected to not happen because we are the creators.
            logger.log(Level.FINE, "Failed to set message type.", iaex);
        }
        createPermissionRequest.addAttribute(
                AttributeFactory.createXorPeerAddressAttribute(
                        peerAddress,
                        transactionID));
        return createPermissionRequest;
    }

    /**
     * Create a Send Indication.
     *
     * @param peerAddress peer address
     * @param data data (could be 0 byte)
     * @param tranID the ID of the transaction that we should be using
     *
     * @return send indication message
     */
    public static Indication createSendIndication(
                    TransportAddress peerAddress, byte[] data, byte[] tranID)
    {
        Indication sendIndication = new Indication();

        try
        {
            sendIndication.setMessageType(Message.SEND_INDICATION);

            /* add XOR-PEER-ADDRESS attribute */
            XorPeerAddressAttribute peerAddressAttribute = AttributeFactory
                            .createXorPeerAddressAttribute(peerAddress, tranID);
            sendIndication.addAttribute(peerAddressAttribute);

            /* add DATA if data */
            if (data != null && data.length > 0)
            {
                DataAttribute dataAttribute = AttributeFactory
                                .createDataAttribute(data);
                sendIndication.addAttribute(dataAttribute);
            }
        } catch (IllegalArgumentException ex)
        {
            logger.log(Level.FINE, "Failed to set message type.", ex);
        }

        return sendIndication;
    }

    /**
     * Create a old Send Request.
     * @param username the username
     * @param peerAddress peer address
     * @param data data (could be 0 byte)
     * @return send indication message
     */
    public static Request createSendRequest(
                    String username, TransportAddress peerAddress, byte[] data)
    {
        Request sendRequest = new Request();

        try
        {
            sendRequest.setMessageType(Message.SEND_REQUEST);

            /* add MAGIC-COOKIE attribute */
            sendRequest.addAttribute(
                    AttributeFactory.createMagicCookieAttribute());

            /* add USERNAME attribute */
            sendRequest.addAttribute(
                    AttributeFactory.createUsernameAttribute(username));

            /* add DESTINATION-ADDRESS attribute */
            DestinationAddressAttribute peerAddressAttribute = AttributeFactory
                            .createDestinationAddressAttribute(peerAddress);
            sendRequest.addAttribute(peerAddressAttribute);

            /* add DATA if data */
            if (data != null && data.length > 0)
            {
                DataAttribute dataAttribute = AttributeFactory
                                .createDataAttributeWithoutPadding(data);
                sendRequest.addAttribute(dataAttribute);
            }
        }
        catch (IllegalArgumentException ex)
        {
            logger.log(Level.FINE, "Failed to set message type.", ex);
        }

        return sendRequest;
    }

    // ======================== NOT CURRENTLY SUPPORTED
    /**
     * Create a shared secret request.
     * WARNING: This is not currently supported.
     *
     * @return request
     */
    public static Request createSharedSecretRequest()
    {
        throw new UnsupportedOperationException(
                        "Shared Secret Support is not currently implemented");
    }

    /**
     * Create a shared secret response.
     * WARNING: This is not currently supported.
     *
     * @return response
     */
    public static Response createSharedSecretResponse()
    {
        throw new UnsupportedOperationException(
                        "Shared Secret Support is not currently implemented");
    }

    /**
     * Create a shared secret error response.
     * WARNING: This is not currently supported.
     *
     * @return error response
     */
    public static Response createSharedSecretErrorResponse()
    {
        throw new UnsupportedOperationException(
                        "Shared Secret Support is not currently implemented");
    }
}
