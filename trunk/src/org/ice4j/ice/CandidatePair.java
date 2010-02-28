/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.util.logging.*;

/**
 * <tt>CandidatePair</tt>s map local to remote <tt>Candidate</tt>s so that they
 * could be added to check lists. Connectivity in ICE is always verified by
 * pairs: i.e. STUN packets are sent from the local candidate of a pair to the
 * remote candidate of a pair. To see which pairs work, an agent schedules a
 * series of <tt>ConnectivityCheck</tt>s. Each check is a STUN request/response
 * transaction that the client will perform on a particular candidate pair by
 * sending a STUN request from the local candidate to the remote candidate.
 *
 * @author Emil Ivov
 */
public class CandidatePair
{
    /**
     * The <tt>Logger</tt> used by the <tt>CandidatePair</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger
                    .getLogger(CandidatePair.class.getName());

    /**
     * The local candidate of this pair.
     */
    private final LocalCandidate localCandidate;

    /**
     * The remote candidate of this pair.
     */
    private final RemoteCandidate remoteCandidate;

    /**
     * Priority of the candidate-pair
     */
    private long priority = 0;

    public static enum CandidatePairState{
    /**
     * Indicates that the candidate pair is in a Waiting state which means that
     * a check has not been performed for this pair, and can be performed as
     * soon as it is the highest priority Waiting pair on the check list.
     */
    STATE_WAITING("Waiting"),

    /**
     * Indicates that the candidate pair is in a "In-Progress" state which means that
     * a check has been sent for this pair, but the transaction is in progress.
     */
    public static final String STATE_IN_PROGRESS = "In-Progress";

    /**
     * Indicates that the candidate pair is in a "Succeeded" state which means
     * that a check for this pair was already done and produced a successful
     * result.
     */
    public static final String STATE_SUCCEEDED = "Succeeded";

    /**
     * Indicates that the candidate pair is in a "Failed" state which means that
     * a check for this pair was already done and failed, either never producing
     * any response or producing an unrecoverable failure response.
     */
    public static final String STATE_FAILED = "Failed";

    /**
     * Indicates that the candidate pair is in a "Frozen" state which means that
     * a check for this pair hasn't been performed, and it can't yet be
     * performed until some other check succeeds, allowing this pair to unfreeze
     * and move into the Waiting state.
     */
    public static final String STATE_FROZEN = "Frozen";
    }
    /**
     * Each candidate pair has a a state that is assigned once the check list
     * for each media stream has been computed. The ICE RFC defines five
     * potential values that the state can have. They are represented here with
     * the STATE_XXX class fields.
     */
    private CandidatePairState state = CandidatePairState.STATE_FROZEN;

    /**
     * Creates a <tt>CandidatePair</tt> instance mapping <tt>localCandidate</tt>
     * to <tt>remoteCandidate</tt>.
     *
     * @param localCandidate the local candidate of the pair.
     * @param remoteCandidate the remote candidate of the pair.
     */
    public CandidatePair(LocalCandidate localCandidate,
                         RemoteCandidate remoteCandidate)
    {

        this.localCandidate = localCandidate;
        this.remoteCandidate = remoteCandidate;
    }
}
