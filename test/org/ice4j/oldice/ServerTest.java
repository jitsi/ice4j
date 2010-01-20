package org.ice4j.oldice;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;


public class ServerTest {
	
	private static final Logger logger =
			Logger.getLogger(ServerTest.class.getName());
	
	private StunStack stunStack = null;
	
	private StunProvider stunProvider = null;
	
	/**
	 * The network access point which the server listens on
	 * for testing lets just use one apDescriptor
	 */
	private NetAccessPointDescriptor apDescriptor = null;
	
	private volatile boolean reqRecvd = false;
	
	private Object lock = new Object();
	
	/**
	 * Initialize the ServerTest class
	 * 
	 * @param apDescriptor the NetAccessPointDescriptor which represents the
	 *                     Transport Address which the server listens on
	 */
	public ServerTest(NetAccessPointDescriptor apDescriptor) 
	{
		this.apDescriptor = apDescriptor;
	}
	
	/**
	 * Shuts down the server
	 */
	public void shutDown() 
	{
		stunStack.removeNetAccessPoint(apDescriptor);		/* remove the NetAccessPoint which was installed */
		
		stunStack = null;		
		
		stunProvider = null;
		
	}
	
	/**
	 * Starts the server
	 */
	public void start() {
		stunStack = StunStack.getInstance();
		
		stunProvider = stunStack.getProvider();
		
		try {
			stunStack.installNetAccessPoint(apDescriptor);	/* Install a new NetAccessPont for the server */
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// add the request listener for the specified net access point
		stunProvider.addRequestListener(apDescriptor, new RequestListener(){
			public void requestReceived(StunMessageEvent evt) {
				// TODO Auto-generated method stub
				Message msg = evt.getMessage();
				TransportAddress remoteAdd = evt.getRemoteAddress();
				
				logger.log(Level.INFO, "A new Message is received");
				logger.log(Level.INFO, "Message send from : " + remoteAdd.toString());
				logger.log(Level.INFO, "Message is a " + msg.getName());
				
				try
				{
					Response response = 
						MessageFactory.createBindingResponse(remoteAdd, apDescriptor.getAddress(), 
								apDescriptor.getAddress());
					
					// copy the transaction id of request to response
					byte[] trId = msg.getTransactionID();
					response.setTransactionID(trId);
					
					stunProvider.sendResponse(trId, response, apDescriptor, remoteAdd);
				}
				catch (StunException ex)
				{	
					logger.log(Level.SEVERE, "Some problem", ex);
				}
				catch (IOException ex)
				{
					logger.log(Level.SEVERE, "Error in sending response", ex);
				}
				
				
				synchronized(lock) 
				{
					reqRecvd = true;
					lock.notify();
				}
				
			}			
		});
		
		while(true)
		{
			synchronized(lock)
			{
				try {
					lock.wait();
				} catch (InterruptedException e) {
					if(reqRecvd)
					{
					    reqRecvd = false;
						break;
					}
				}
			}
		}
	}
	
	public static void main(String []args)
	{
		NetAccessPointDescriptor apDescriptor = new NetAccessPointDescriptor(
				                                new TransportAddress("localhost", 4006));
		
		final ServerTest serverTest = new ServerTest(apDescriptor);
		logger.log(Level.INFO, "Server Started....");
		Thread newservThread = new Thread(new Runnable() {

			public void run() {
				serverTest.start();
			}
			
		});
		
		newservThread.start();
		
		/* NOTE : This server must be terminated manually */
		
		//serverTest.shutDown();
		//logger.log(Level.INFO, "Server terminated");
		
		
	}
}
