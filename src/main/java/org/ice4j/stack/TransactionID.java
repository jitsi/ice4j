/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
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
package org.ice4j.stack;

import java.util.*;

/**
 * This class encapsulates a STUN transaction ID. It is useful for storing
 * transaction IDs in collection objects as it implements the equals method.
 * It also provides a utility for creating unique transaction IDs.
 *
 * @author Emil Ivov
 */
public class TransactionID
{
    /**
     * RFC5289 Transaction ID length.
     */
    public static final int RFC5389_TRANSACTION_ID_LENGTH = 12;

    /**
     * RFC3489 Transaction ID length.
     */
    public static final int RFC3489_TRANSACTION_ID_LENGTH = 16;

    /**
     * The object to use to generate the rightmost 8 bytes of the id.
     */
    private static final Random random
        = new Random();

    /**
     * The byte-array representing transaction ID value
     */
    private final byte[] transactionID;

    /**
     * A pre-computed hash code, assuming transactionID content is
     * not changed after object creation
     */
    private final int hashCode;

    /**
     * Any object that the application would like to correlate to a transaction.
     */
    private Object applicationData = null;

    /**
     * Construct TransactionID object from passed byte array.
     * Constructed object is suitable to store in hashable data structure.
     * @param tid - byte array value of transaction ID. It is assumed that
     *            it is not modified after construction. Array length must be
     *            either {@link #RFC5389_TRANSACTION_ID_LENGTH} or
     *            {@link #RFC3489_TRANSACTION_ID_LENGTH}
     */
    private TransactionID(byte[] tid)
    {
        if (tid.length != RFC3489_TRANSACTION_ID_LENGTH &&
            tid.length != RFC5389_TRANSACTION_ID_LENGTH)
        {
            throw new IllegalArgumentException("Illegal length");
        }

        // assuming passed tid byte-array will not be modified
        this.transactionID = tid;

        // pre-compute hash code assuming no-one is changing tid byte-array
        this.hashCode = Arrays.hashCode(tid);
    }

    /**
     * Creates a transaction id object.The transaction id itself is generated
     * using the following algorithm:
     *
     * The first 6 bytes of the id are given the value of
     * <tt>System.currentTimeMillis()</tt>. Putting the right most bits first
     * so that we get a more optimized equals() method.
     *
     * @return A <tt>TransactionID</tt> object with a unique transaction id.
     */
    public static TransactionID createNewTransactionID()
    {
        TransactionID tid = new TransactionID(
            generateTransactionID(RFC5389_TRANSACTION_ID_LENGTH));
        return tid;
    }

    /**
     * Creates a RFC3489 transaction id object.The transaction id itself is
     * generated using the following algorithm:
     *
     * The first 8 bytes of the id are given the value of
     * <tt>System.currentTimeMillis()</tt>. Putting the right most bits first
     * so that we get a more optimized equals() method.
     *
     * @return A <tt>TransactionID</tt> object with a unique transaction id.
     */
    public static TransactionID createNewRFC3489TransactionID()
    {
        TransactionID tid = new TransactionID(
            generateTransactionID(RFC3489_TRANSACTION_ID_LENGTH));
        return tid;
    }

    /**
     * Generates a random transaction ID with specified length
     *
     * @param nb number of bytes to generate
     * @return byte-array with random byte content
     */
    private static byte[] generateTransactionID(int nb)
    {
        long left  = System.currentTimeMillis();//the first nb/2 bytes of the id
        long right = random.nextLong();//the last nb/2 bytes of the id
        int b = nb / 2;
        byte[] tid = new byte[nb];

        for(int i = 0; i < b; i++)
        {
            tid[i]   = (byte)((left  >> (i * 8)) & 0xFFL);
            tid[i + b] = (byte)((right >> (i * 8)) & 0xFFL);
        }
        return tid;
    }

    /**
     * Returns a <tt>TransactionID</tt> instance for the specified id. If
     * <tt>transactionID</tt> is the ID of a client or a server transaction
     * already known to the stack, then this method would return a reference
     * to that transaction's instance so that we could use it to for storing
     * application data.
     *
     * @param stunStack the <tt>StunStack</tt> in the context of which the
     * request to create a <tt>TransactionID</tt> is being made
     * @param transactionID the value of the ID.
     *
     * @return a reference to the (possibly already existing)
     * <tt>TransactionID</tt> corresponding to the value of
     * <tt>transactionID</tt>
     */
    public static TransactionID createTransactionID(
            StunStack stunStack,
            byte[] transactionID)
    {
        //first check whether we can find a client or a server tran with the
        //specified id.
        StunClientTransaction cliTran
            = stunStack.getClientTransaction(transactionID);

        if(cliTran != null)
            return cliTran.getTransactionID();

        StunServerTransaction serTran
            = stunStack.getServerTransaction(transactionID);

        if(serTran != null)
            return serTran.getTransactionID();

        // Perform defensive-cloning of byte-array not to break existing code
        return new TransactionID(transactionID.clone());
    }

    /**
     * Returns the transaction id byte array (length 12 or 16 if RFC3489
     * compatible).
     *
     * @return the transaction ID byte array.
     */
    public byte[] getBytes()
    {
        return transactionID;
    }

    /**
     * If the transaction is compatible with RFC3489 (16 bytes).
     *
     * @return true if transaction ID is compatible with RFC3489
     */
    public boolean isRFC3489Compatible()
    {
        return (transactionID.length == RFC3489_TRANSACTION_ID_LENGTH);
    }

    /**
     * Compares two TransactionID objects.
     * @param obj the object to compare with.
     * @return true if the objects are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if(this == obj)
        {
            return true;
        }
        if(!(obj instanceof TransactionID))
        {
            return false;
        }
        return this.equals(((TransactionID)obj).transactionID);
    }

    /**
     * Compares the specified byte array with this transaction id.
     * @param targetID the id to compare with ours.
     * @return true if targetID matches this transaction id.
     */
    public boolean equals(byte[] targetID)
    {
        return Arrays.equals(transactionID, targetID);
    }

    /**
     * Returns a hash code value for the object. This method is
     * supported for the benefit of hash tables such as those provided by
     * {@link java.util.HashMap}.
     * @return  a hash code value for this object.
     */
    @Override
    public int hashCode()
    {
        return hashCode;
    }

    /**
     * Returns a string representation of the ID
     *
     * @return a hex string representing the id
     */
    public String toString()
    {
        return TransactionID.toString(transactionID);
    }

    /**
     * Returns a string representation of the ID
     *
     * @param transactionID the transaction ID to convert into <tt>String</tt>.
     *
     * @return a hex string representing the id
     */
    public static String toString(byte[] transactionID)
    {
        StringBuilder idStr = new StringBuilder();

        idStr.append("0x");
        for(int i = 0; i < transactionID.length; i++)
        {

            if((transactionID[i] & 0xFF) <= 15)
                idStr.append("0");

            idStr.append(
                    Integer.toHexString(transactionID[i] & 0xFF).toUpperCase());
        }

        return idStr.toString();
    }

    /**
     * Stores <tt>applicationData</tt> in this ID so that we can refer back to
     * it if we ever need to at a later stage (e.g. when receiving a response
     * to a {@link StunClientTransaction}).
     *
     * @param applicationData a reference to the {@link Object} that the
     * application would like to correlate to the transaction represented by
     * this ID.
     */
    public void setApplicationData(Object applicationData)
    {
        this.applicationData = applicationData;
    }

    /**
     * Returns whatever <tt>applicationData</tt> was previously stored in this
     * ID.
     *
     * @return a reference to the {@link Object} that the application may have
     * stored in this ID's application data field.
     */
    public Object getApplicationData()
    {
        return applicationData;
    }
}
