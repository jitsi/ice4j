package org.ice4j.oldice;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.ice4j.*;
import org.ice4j.oldice.*;


public class CheckListTest
{
    private static final Logger logger =
        Logger.getLogger(CheckListTest.class.getName());

    private IceAgent iceAgent;

    public CheckListTest()
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

        MediaStream audioStream = iceAgent.getMediaStream("audio");

        audioStream.createComponent("UDP", new TransportAddress("192.168.1.23", 6001));
        logger.log(Level.INFO, "Component 1 of audio stream created with default port 6001");

        audioStream.createComponent("UDP", new TransportAddress("192.168.1.23", 6002));
        logger.log(Level.INFO, "Component 2 of audio stream created with default port 6002");

        MediaStream videoStream = iceAgent.getMediaStream("video");

        videoStream.createComponent("UDP", new TransportAddress("192.168.1.23", 7001));
        logger.log(Level.INFO, "Component 1 of video stream created with default port 7001");

        videoStream.createComponent("UDP", new TransportAddress("192.168.1.23", 7002));
        logger.log(Level.INFO, "Component 2 of video stream created with default port 7002");


        List<Component> compList1 = audioStream.getComponentsList();
        List<Component> compList2 = videoStream.getComponentsList();


        Candidate base;
        try {
        // ---- creating local candidates for audio stream  -----------------------//

            Candidate candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.168.6.125"), 8003),
                    compList1.get(0));
            candidate.setCandidateType(Candidate.HOST_CANDIDATE);
            candidate.setBase(candidate);
            candidate.setFoundation("1");
            candidate.setPriority(Candidate.computePriority(candidate));
            audioStream.addLocalCandidate(candidate);

            base = candidate;

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.248.6.126"), 8004),
                    compList1.get(0));
            candidate.setCandidateType(Candidate.SERVER_REFLEXIVE_CANDIDATE);
            candidate.setBase(base);
            candidate.setFoundation("2");
            candidate.setPriority(Candidate.computePriority(candidate));
            audioStream.addLocalCandidate(candidate);
            //  -------- end of creating candidates for component 1 -------

            // ---- creating candidates for component 2  ----------
            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.168.6.125"), 8005),
                    compList1.get(1));
            candidate.setCandidateType(Candidate.HOST_CANDIDATE);
            candidate.setBase(candidate);
            candidate.setFoundation("1");
            candidate.setPriority(Candidate.computePriority(candidate));
            audioStream.addLocalCandidate(candidate);

            base = candidate;

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.248.6.126"), 8006),
                    compList1.get(1));
            candidate.setCandidateType(Candidate.SERVER_REFLEXIVE_CANDIDATE);
            candidate.setBase(base);
            candidate.setFoundation("2");
            candidate.setPriority(Candidate.computePriority(candidate));
            audioStream.addLocalCandidate(candidate);
            // --- end of creating candidates for component 2

        // ~//----- end of creating local candidates for audio stream ----------------//


        // ----- creating local candidates for video stream ---------------------//

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.168.6.125"), 8007),
                    compList1.get(0));
            candidate.setCandidateType(Candidate.HOST_CANDIDATE);
            candidate.setBase(candidate);
            candidate.setFoundation("1");
            candidate.setPriority(Candidate.computePriority(candidate));
            videoStream.addLocalCandidate(candidate);

            base = candidate;

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.248.6.126"), 8008),
                    compList1.get(0));
            candidate.setCandidateType(Candidate.SERVER_REFLEXIVE_CANDIDATE);
            candidate.setBase(base);
            candidate.setFoundation("2");
            candidate.setPriority(Candidate.computePriority(candidate));
            videoStream.addLocalCandidate(candidate);
            //  -------- end of creating candidates for component 1 -------

            // ---- creating candidates for component 2  ----------
            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.168.6.125"), 8009),
                    compList1.get(1));
            candidate.setCandidateType(Candidate.HOST_CANDIDATE);
            candidate.setBase(candidate);
            candidate.setFoundation("1");
            candidate.setPriority(Candidate.computePriority(candidate));
            videoStream.addLocalCandidate(candidate);

            base = candidate;

            candidate = new Candidate(
                    new TransportAddress(InetAddress.getByName("192.248.6.126"), 8010),
                    compList1.get(1));
            candidate.setCandidateType(Candidate.SERVER_REFLEXIVE_CANDIDATE);
            candidate.setBase(base);
            candidate.setFoundation("2");
            candidate.setPriority(Candidate.computePriority(candidate));
            videoStream.addLocalCandidate(candidate);
            // --- end of creating candidates for component 2

        // ~//------ end of creating local candidates for video stream -------------//

        // --------------------------------------------------------------------------------------------//

        // ---- Creating  remote candidates for audio stream ----------------------//

            // ------- create candidates for Component 1 -------------
            candidate = new Candidate(
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

        // ---------- end of creating remote candidates for audio stream  --------------------//

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

        // ----------- end of creating remote candidates for video stream ------------//

        } catch (UnknownHostException e) {
            logger.log(Level.SEVERE, "Error in creating the InetAddress", e);
        }
    }

    public void createCheckLists()
        throws IceException
    {
        MediaStream audioStream = iceAgent.getMediaStream("audio");
        MediaStream videoStream = iceAgent.getMediaStream("video");

        audioStream.createCheckList();
        videoStream.createCheckList();
    }

    public static void main(String[] args)
        throws IceException
    {
        CheckListTest test = new CheckListTest();

        test.createMediaStreams();
        test.createCheckLists();
    }
}
