package org.ice4j.oldice;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.ice4j.*;
import org.ice4j.oldice.*;


/**
 * This test class describes the first part of ICE processing
 * 1) Gathering candidates
 * 2) Prioritizing candidates
 * 3) Removing redundant candidates
 *
 * First the application creates two media streams
 *      i)  audio media stream with name "audio"
 *      ii) video media stream with name "video"
 *
 * Secondly, two components are created for each media stream
 *
 * Then the STUN server address is set, the server address is hard coded
 * Please make sure to run the ServerTest program, before running this program
 * ServerTest runs on port 4006
 *
 * Then, the IceAgent gathers candidates for each and every component
 * Log messages are printed specifying the type of the candidate (e.g Host or
 * ServerReflexive) Inside the same method call, Foundations of candidates are
 * calculated
 *
 * Then Redundant candidates are removed from each and every component
 * Log messages are printed as redundant candidates are identified
 *
 * Valid candidates for the component can be identified by reading through the
 * log messages. When ever a candidate is printed, its associated Component and
 * MediaStream is also printed.
 *
 *
 * @author Namal Senarathne
 */
public class IceTest {

    private static final Logger logger =
        Logger.getLogger(IceTest.class.getName());

    private IceAgent iceAgent;


    public IceTest()
    {
        iceAgent = new IceAgent();
    }

    public void createMediaStreams()
        throws IceException
    {
        iceAgent.addMediaStream("audio");
        logger.log(Level.INFO, "Media Stream [audio] created");

        iceAgent.addMediaStream("video");
        logger.log(Level.INFO, "Media Stream [video] created");
    }

    public void createComponents()
        throws IceException
    {
        MediaStream audioStream = iceAgent.getMediaStream("audio");

        audioStream.createComponent("UDP", new TransportAddress("localhost", 6001));
        logger.log(Level.INFO, "Component 1 of audio stream created with default port 6001");

        audioStream.createComponent("UDP", new TransportAddress("localhost", 6002));
        logger.log(Level.INFO, "Component 2 of audio stream created with default port 6002");

        MediaStream videoStream = iceAgent.getMediaStream("video");

        videoStream.createComponent("UDP", new TransportAddress("localhost", 7001));
        logger.log(Level.INFO, "Component 1 of video stream created with default port 7001");

        videoStream.createComponent("UDP", new TransportAddress("localhost", 7002));
        logger.log(Level.INFO, "Component 2 of video stream created with default port 7002");
    }

    public void setStunServerAddress()
    {
        iceAgent.setStunServerAddress(new TransportAddress("localhost", 4006));
        logger.log(Level.INFO, "Setting STUN server address to [localhost:4006]");
    }

    public void gatherCandidates()
        throws IceException
    {
        logger.log(Level.INFO, "Starting gathering candidates operation...");
        iceAgent.gatherCandidates();
    }

    public void prioritizeCandidates()
    {
        logger.log(Level.INFO, "Starting prioritizing candidates...");
        iceAgent.prioritizeCandidates();
    }

    public void testCreateCheckList()
        throws IceException
    {
        //--------------  First create the Remote candidates -------------------//

        MediaStream audioStream = iceAgent.getMediaStream("audio");
        MediaStream videoStream = iceAgent.getMediaStream("video");

        List<Component> compList1 = audioStream.getComponentsList();
        List<Component> compList2 = videoStream.getComponentsList();


        Candidate base;
        try {

        // ---- Creating candidates for audio stream ----------------------//

            // ------- create candidates for Component 1 -------------
            Candidate candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.168.5.125"), 2003),
                    compList1.get(0));
            candidate.setCandidateType(Candidate.HOST_CANDIDATE);
            candidate.setBase(candidate);
            candidate.setFoundation("1");
            candidate.setPriority(Candidate.computePriority(candidate));
            audioStream.addRemoteCandidate(candidate);

            base = candidate;

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.248.5.126"), 2004),
                    compList1.get(0));
            candidate.setCandidateType(Candidate.SERVER_REFLEXIVE_CANDIDATE);
            candidate.setBase(base);
            candidate.setFoundation("2");
            candidate.setPriority(Candidate.computePriority(candidate));
            audioStream.addRemoteCandidate(candidate);
            //  -------- end of creating candidates for component 1 -------

            // ---- creating candidates for component 2  ----------
            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.168.5.125"), 2005),
                    compList1.get(1));
            candidate.setCandidateType(Candidate.HOST_CANDIDATE);
            candidate.setBase(candidate);
            candidate.setFoundation("1");
            candidate.setPriority(Candidate.computePriority(candidate));
            audioStream.addRemoteCandidate(candidate);

            base = candidate;

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.248.5.126"), 2006),
                    compList1.get(1));
            candidate.setCandidateType(Candidate.SERVER_REFLEXIVE_CANDIDATE);
            candidate.setBase(base);
            candidate.setFoundation("2");
            candidate.setPriority(Candidate.computePriority(candidate));
            audioStream.addRemoteCandidate(candidate);
            // --- end of creating candidates for component 2

        // ---------- end of creating candidates for audio stream  --------------------//

        // ----------- creating candidates for video stream ------------------ //

            // ---- creating candidates for component 1
            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.168.5.125"), 2007),
                    compList2.get(0));
            candidate.setCandidateType(Candidate.HOST_CANDIDATE);
            candidate.setBase(candidate);
            candidate.setFoundation("1");
            candidate.setPriority(Candidate.computePriority(candidate));
            videoStream.addRemoteCandidate(candidate);

            base = candidate;

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.248.5.126"), 2008),
                    compList2.get(0));
            candidate.setCandidateType(Candidate.SERVER_REFLEXIVE_CANDIDATE);
            candidate.setBase(base);
            candidate.setFoundation("2");
            candidate.setPriority(Candidate.computePriority(candidate));
            videoStream.addRemoteCandidate(candidate);

            // --------- end of creating candidates for component 1 ---------//

            // --- creating candidates for component 2 ----------- //

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.168.5.125"), 2009),
                    compList2.get(1));
            candidate.setCandidateType(Candidate.HOST_CANDIDATE);
            candidate.setBase(candidate);
            candidate.setFoundation("1");
            candidate.setPriority(Candidate.computePriority(candidate));
            videoStream.addRemoteCandidate(candidate);

            base = candidate;

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.248.5.126"), 2010),
                    compList2.get(1));
            candidate.setCandidateType(Candidate.SERVER_REFLEXIVE_CANDIDATE);
            candidate.setBase(base);
            candidate.setFoundation("2");
            candidate.setPriority(Candidate.computePriority(candidate));
            videoStream.addRemoteCandidate(candidate);

            // --- end of creating candidates for component 2 ------- //

        // ----------- end of creating candidates for video stream ------------//

        } catch (UnknownHostException e) {
            logger.log(Level.SEVERE, "Error in creating the InetAddress");
        }

        // ---------------- End of creating remote candidates -------------------------//

        audioStream.createCheckList();
        videoStream.createCheckList();
    }

    public static void main(String[] args)
        throws IceException
    {
        IceTest iceTest = new IceTest();

        iceTest.createMediaStreams();
        iceTest.createComponents();

        /* Stun Server must be set before gathering candidates */
        iceTest.setStunServerAddress();
        iceTest.gatherCandidates();

        iceTest.prioritizeCandidates();

        iceTest.testCreateCheckList();
    }

}
