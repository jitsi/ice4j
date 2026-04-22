/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2026 8x8, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ice4j.message;

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.security.*;
import org.ice4j.stack.*;
import org.jitsi.config.*;
import org.junit.jupiter.api.*;

/**
 * Unit tests for {@link StunStack#validateMessageIntegrity} and for the
 * RFC 5389 rule that attributes appearing after MESSAGE-INTEGRITY are
 * silently ignored during decoding (FINGERPRINT excepted).
 */
public class MessageIntegrityTest
{
    /** Local ICE fragment used as the short-term credential username. */
    private static final String LFRAG = "testlfrag";

    /** Password/key returned by the credentials authority for {@link #LFRAG}. */
    private static final byte[] KEY = "testpassword".getBytes();

    @BeforeAll
    public static void setupConfig()
    {
        System.clearProperty(StackProperties.ALWAYS_SIGN);
        System.setProperty("ice4j.software", "");
        JitsiConfig.Companion.reloadNewConfig();
    }

    @AfterAll
    public static void resetConfig()
    {
        System.clearProperty("ice4j.software");
        JitsiConfig.Companion.reloadNewConfig();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Builds a raw STUN Binding Success Response that contains a single
     * MESSAGE-INTEGRITY attribute whose HMAC-SHA1 value is computed from
     * {@link #KEY} without going through the encode pipeline.
     *
     * <p>Wire layout (44 bytes total):
     * <pre>
     *   [0..19]  20-byte STUN header  (length field = 24, i.e. one attr)
     *   [20..43] MESSAGE-INTEGRITY attr (4-byte TLV header + 20-byte HMAC)
     * </pre>
     *
     * <p>The HMAC is computed over bytes [0..19] with the length field already
     * set to 24, exactly as {@link StunStack#validateMessageIntegrity} will
     * re-derive it.
     */
    private static byte[] buildRawResponseWithIntegrity(byte[] key)
    {
        // --- build the 20-byte STUN header ---
        byte[] header = new byte[Message.HEADER_LENGTH];
        // Type: Binding Success Response = 0x0101
        header[0] = 0x01;
        header[1] = 0x01;
        // Length of attributes = size of MESSAGE-INTEGRITY attr = 24
        header[2] = 0x00;
        header[3] = 0x18;
        // Magic cookie
        header[4] = 0x21;
        header[5] = 0x12;
        header[6] = (byte) 0xA4;
        header[7] = 0x42;
        // Transaction ID (use the fixture constant)
        System.arraycopy(MsgFixture.TRANSACTION_ID, 0, header, 8, 12);

        // HMAC over the header (with length already set to 24)
        byte[] hmac = MessageIntegrityAttribute.calculateHmacSha1(
            header, 0, header.length, key);

        // --- assemble the full message ---
        byte[] msg = new byte[Message.HEADER_LENGTH
            + Attribute.HEADER_LENGTH
            + MessageIntegrityAttribute.DATA_LENGTH]; // 20 + 4 + 20 = 44
        System.arraycopy(header, 0, msg, 0, Message.HEADER_LENGTH);
        // MESSAGE-INTEGRITY TLV header
        msg[20] = 0x00;
        msg[21] = 0x08; // type = MESSAGE_INTEGRITY
        msg[22] = 0x00;
        msg[23] = 0x14; // length = 20
        // HMAC value
        System.arraycopy(hmac, 0, msg, 24, hmac.length);

        return msg;
    }

    /**
     * Decodes {@code rawBytes} and returns the MESSAGE-INTEGRITY attribute
     * (which will have its {@code locationInMessage} set correctly).
     */
    private static MessageIntegrityAttribute decodeMsgIntAttr(byte[] rawBytes)
        throws StunException
    {
        Message decoded = Message.decode(rawBytes, 0, rawBytes.length);
        return (MessageIntegrityAttribute)
            decoded.getAttribute(Attribute.MESSAGE_INTEGRITY);
    }

    /**
     * Creates a {@link RawMessage} wrapping the given bytes, using placeholder
     * transport addresses.
     */
    private static RawMessage rawMessage(byte[] bytes)
        throws Exception
    {
        TransportAddress addr =
            new TransportAddress("127.0.0.1", 5000, Transport.UDP);
        return RawMessage.build(bytes, bytes.length, addr, addr);
    }

    /**
     * Returns a {@link StunStack} whose credentials manager will answer
     * {@link #LFRAG} → {@link #KEY} for local-key lookups.
     */
    private static StunStack stunStackWithKey(String lfrag, byte[] key)
    {
        StunStack stack = new StunStack();
        stack.getCredentialsManager().registerAuthority(new CredentialsAuthority()
        {
            @Override
            public byte[] getLocalKey(String username)
            {
                return lfrag.equals(username) ? key.clone() : null;
            }

            @Override
            public byte[] getRemoteKey(String username, String media)
            {
                return null;
            }

            @Override
            public boolean checkLocalUserName(String username)
            {
                return lfrag.equals(username);
            }
        });
        return stack;
    }

    // -------------------------------------------------------------------------
    // validateMessageIntegrity tests
    // -------------------------------------------------------------------------

    /**
     * A message with a correctly computed HMAC-SHA1 must pass integrity
     * validation.
     */
    @Test
    public void testValidateMessageIntegrity_valid()
        throws Exception
    {
        byte[] rawBytes = buildRawResponseWithIntegrity(KEY);
        MessageIntegrityAttribute msgInt = decodeMsgIntAttr(rawBytes);
        RawMessage rawMessage = rawMessage(rawBytes);

        StunStack stack = stunStackWithKey(LFRAG, KEY);

        // Short-term: username = "lfrag:remoteUser"
        assertTrue(
            stack.validateMessageIntegrity(
                msgInt, LFRAG + ":remoteUser", true, rawMessage),
            "Should accept a correctly signed message");
    }

    /**
     * Flipping any bit of the HMAC value must cause validation to fail.
     */
    @Test
    public void testValidateMessageIntegrity_tamperedHmac()
        throws Exception
    {
        byte[] rawBytes = buildRawResponseWithIntegrity(KEY);

        // Corrupt the last byte of the HMAC (last byte of the whole message)
        rawBytes[rawBytes.length - 1] ^= (byte) 0xFF;

        MessageIntegrityAttribute msgInt = decodeMsgIntAttr(rawBytes);
        RawMessage rawMessage = rawMessage(rawBytes);

        StunStack stack = stunStackWithKey(LFRAG, KEY);

        assertFalse(
            stack.validateMessageIntegrity(
                msgInt, LFRAG + ":remoteUser", true, rawMessage),
            "Should reject a message with a tampered HMAC");
    }

    /**
     * A null username must be rejected immediately, before any HMAC work.
     */
    @Test
    public void testValidateMessageIntegrity_nullUsername()
        throws Exception
    {
        byte[] rawBytes = buildRawResponseWithIntegrity(KEY);
        MessageIntegrityAttribute msgInt = decodeMsgIntAttr(rawBytes);
        RawMessage rawMessage = rawMessage(rawBytes);

        StunStack stack = stunStackWithKey(LFRAG, KEY);

        assertFalse(
            stack.validateMessageIntegrity(msgInt, null, true, rawMessage),
            "Should reject null username");
    }

    /**
     * An empty username must be rejected immediately.
     */
    @Test
    public void testValidateMessageIntegrity_emptyUsername()
        throws Exception
    {
        byte[] rawBytes = buildRawResponseWithIntegrity(KEY);
        MessageIntegrityAttribute msgInt = decodeMsgIntAttr(rawBytes);
        RawMessage rawMessage = rawMessage(rawBytes);

        StunStack stack = stunStackWithKey(LFRAG, KEY);

        assertFalse(
            stack.validateMessageIntegrity(msgInt, "", true, rawMessage),
            "Should reject empty username");
    }

    /**
     * In short-term credential mode the username must contain a colon
     * separating the local and remote frags.  A bare lfrag (no colon) must
     * be rejected.
     */
    @Test
    public void testValidateMessageIntegrity_shortTermUsernameWithoutColon()
        throws Exception
    {
        byte[] rawBytes = buildRawResponseWithIntegrity(KEY);
        MessageIntegrityAttribute msgInt = decodeMsgIntAttr(rawBytes);
        RawMessage rawMessage = rawMessage(rawBytes);

        StunStack stack = stunStackWithKey(LFRAG, KEY);

        assertFalse(
            stack.validateMessageIntegrity(msgInt, LFRAG, true, rawMessage),
            "Should reject short-term username that has no colon");
    }

    /**
     * When the lfrag extracted from the username is not known to the
     * credentials manager, validation must fail.
     */
    @Test
    public void testValidateMessageIntegrity_unknownUsername()
        throws Exception
    {
        byte[] rawBytes = buildRawResponseWithIntegrity(KEY);
        MessageIntegrityAttribute msgInt = decodeMsgIntAttr(rawBytes);
        RawMessage rawMessage = rawMessage(rawBytes);

        StunStack stack = stunStackWithKey(LFRAG, KEY);

        assertFalse(
            stack.validateMessageIntegrity(
                msgInt, "unknownlfrag:remoteUser", true, rawMessage),
            "Should reject a username unknown to the credentials manager");
    }

    /**
     * In long-term credential mode the full username string is used directly
     * for the key lookup (no colon splitting).  A matching key must cause
     * validation to succeed.
     */
    @Test
    public void testValidateMessageIntegrity_longTermValid()
        throws Exception
    {
        byte[] rawBytes = buildRawResponseWithIntegrity(KEY);
        MessageIntegrityAttribute msgInt = decodeMsgIntAttr(rawBytes);
        RawMessage rawMessage = rawMessage(rawBytes);

        StunStack stack = stunStackWithKey(LFRAG, KEY);

        assertTrue(
            stack.validateMessageIntegrity(msgInt, LFRAG, false, rawMessage),
            "Should accept a valid long-term credential");
    }

    // -------------------------------------------------------------------------
    // Tests for RFC 5389 §15.4 — attributes after MESSAGE-INTEGRITY
    // -------------------------------------------------------------------------

    /**
     * RFC 5389 §15.4: agents MUST ignore all attributes that follow
     * MESSAGE-INTEGRITY, with the sole exception of FINGERPRINT.
     * Verify that an attribute placed after MESSAGE-INTEGRITY is absent from
     * the decoded message.
     */
    @Test
    public void testDecodeIgnoresAttributesAfterMessageIntegrity()
        throws StunException
    {
        /*
         * Build a Binding Request (manually) with this attribute order:
         *   USERNAME  "user"          8 bytes  (type=0x0006, len=4)
         *   MESSAGE-INTEGRITY         24 bytes (type=0x0008, len=20, dummy HMAC)
         *   CHANGE-REQUEST            8 bytes  (type=0x0003, len=4)  <-- must be ignored
         *
         * Total attributes = 40 bytes; STUN length field = 0x0028.
         */
        byte[] msg = {
            0x00, 0x01,                              // Type: Binding Request
            0x00, 0x28,                              // Length: 40
            0x21, 0x12, (byte) 0xA4, 0x42,          // Magic Cookie
            0x01, 0x02, 0x03, 0x04,                  // Transaction ID (12 bytes)
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
            // USERNAME
            0x00, 0x06,  0x00, 0x04,                 // type, length
            0x75, 0x73,  0x65, 0x72,                 // "user"
            // MESSAGE-INTEGRITY (dummy HMAC — not validated by decode)
            0x00, 0x08,  0x00, 0x14,                 // type, length=20
            0x00, 0x00,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00,
            0x00, 0x00,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00,
            0x00, 0x00,  0x00, 0x00,
            // CHANGE-REQUEST — must be silently ignored
            0x00, 0x03,  0x00, 0x04,                 // type, length
            0x00, 0x00,  0x00, 0x00
        };

        Message decoded = Message.decode(msg, 0, msg.length);

        assertNotNull(decoded.getAttribute(Attribute.USERNAME),
            "USERNAME before MESSAGE-INTEGRITY must be present");
        assertNotNull(decoded.getAttribute(Attribute.MESSAGE_INTEGRITY),
            "MESSAGE-INTEGRITY itself must be present");
        assertNull(decoded.getAttribute(Attribute.CHANGE_REQUEST),
            "CHANGE-REQUEST after MESSAGE-INTEGRITY must be silently ignored");
    }

    /**
     * RFC 5389 §15.4: FINGERPRINT is explicitly exempted from the
     * "ignore after MESSAGE-INTEGRITY" rule.  Verify that a valid FINGERPRINT
     * placed after MESSAGE-INTEGRITY survives decoding.
     */
    @Test
    public void testDecodeFingerprintAfterMessageIntegrityIsNotIgnored()
        throws Exception
    {
        /*
         * Build a Binding Success Response containing:
         *   MESSAGE-INTEGRITY  (dummy HMAC)         24 bytes
         *   FINGERPRINT        (CRC-32 over above)   8 bytes
         *
         * The CRC-32 must be valid; it is computed over the 44 bytes that
         * precede the FINGERPRINT value, with the length field set to 32
         * (MI-size + FP-size = 24 + 8).
         *
         * The HMAC is intentionally left as zeros — Message.decode does not
         * validate MESSAGE-INTEGRITY itself, only FINGERPRINT.
         */
        final int MI_ATTR_LEN  = Attribute.HEADER_LENGTH
            + MessageIntegrityAttribute.DATA_LENGTH; // 24
        final int FP_ATTR_LEN  = Attribute.HEADER_LENGTH + 4;             // 8

        // Allocate the full 52-byte message
        byte[] msg = new byte[Message.HEADER_LENGTH + MI_ATTR_LEN + FP_ATTR_LEN];

        // STUN header
        msg[0] = 0x01; msg[1] = 0x01;                   // Binding Success Response
        msg[2] = 0x00; msg[3] = (byte)(MI_ATTR_LEN + FP_ATTR_LEN); // length = 32
        msg[4] = 0x21; msg[5] = 0x12;
        msg[6] = (byte) 0xA4; msg[7] = 0x42;            // magic cookie
        System.arraycopy(MsgFixture.TRANSACTION_ID, 0, msg, 8, 12);

        // MESSAGE-INTEGRITY attribute (zeros for HMAC)
        int miOffset = Message.HEADER_LENGTH;
        msg[miOffset]     = 0x00; msg[miOffset + 1] = 0x08; // type
        msg[miOffset + 2] = 0x00; msg[miOffset + 3] = 0x14; // length = 20
        // HMAC bytes stay zero

        // FINGERPRINT attribute — compute CRC-32 over bytes 0..(miOffset+MI_ATTR_LEN-1)
        // with the length field already set to 32 (already written above).
        int fpOffset = miOffset + MI_ATTR_LEN; // = 44
        byte[] crc = FingerprintAttribute.calculateXorCRC32(msg, 0, fpOffset);
        msg[fpOffset]     = (byte) 0x80; msg[fpOffset + 1] = 0x28; // type = FINGERPRINT
        msg[fpOffset + 2] = 0x00;        msg[fpOffset + 3] = 0x04; // length = 4
        msg[fpOffset + 4] = crc[0];
        msg[fpOffset + 5] = crc[1];
        msg[fpOffset + 6] = crc[2];
        msg[fpOffset + 7] = crc[3];

        Message decoded = Message.decode(msg, 0, msg.length);

        assertNotNull(decoded.getAttribute(Attribute.MESSAGE_INTEGRITY),
            "MESSAGE-INTEGRITY must be present");
        assertNotNull(decoded.getAttribute(Attribute.FINGERPRINT),
            "FINGERPRINT after MESSAGE-INTEGRITY must not be ignored");
    }
}
