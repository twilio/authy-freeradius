package com.hubcitymedia.authycallback.objects;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class OneTouchPersistence implements ServletContextListener{
	private static ConcurrentHashMap<String, String> requestMap;

	private static String AUTHY_API_KEY;
	private static String AUTHY_LOG_LOCATION;
	
	private static Logger logger = Logger.getLogger("PersistenceLog");
	private static FileHandler fh;

	private void init()
	{
		requestMap = new ConcurrentHashMap<String, String>();
		
		AUTHY_LOG_LOCATION = System.getenv("AUTHY_LOG_LOCATION");
		if(AUTHY_LOG_LOCATION == null)
		{
			//If Authy log location not found, throw exception to catalina output
			System.out.println("Failed to load environmental variable AUTHY_LOG_LOCATION. Ensure it is set in setenv.sh configuration file. Failing startup of application.");
			throw new RuntimeException();
		}
		
		if(fh == null)
		{
			try {
				fh = new FileHandler(AUTHY_LOG_LOCATION+"/Persistence.log", true);
				fh.setFormatter(new SimpleFormatter());
			} catch (SecurityException e) {
				e.printStackTrace();
				throw new RuntimeException();
			} catch (IOException e) {
				e.printStackTrace();
				throw new RuntimeException();
			}
			logger.addHandler(fh);
		}
		logger.info("Getting API KEY from environmental variable");
		AUTHY_API_KEY = System.getenv("AUTHY_API_KEY");
		if(AUTHY_API_KEY == null)
		{
			logger.severe("No API Key found. Make sure setenv.sh contains AUTHY_API_KEY variable. Failing startup.");
			throw new RuntimeException();
		}
	}

	public static String getCallbackStatus(String uuid)
	{
		if(OneTouchPersistence.requestMap.containsKey(uuid))
		{
			//"Pop" item from map
			String status =  OneTouchPersistence.requestMap.get(uuid);
			OneTouchPersistence.requestMap.remove(uuid);
			return status;
		}else
		{
			return null;
		}
	}

	public static void putCallbackStatus(String uuid, String status)
	{
		OneTouchPersistence.requestMap.put(uuid, status);
	}

	public static String getAPIKey()
	{
		return AUTHY_API_KEY;
	}
	
	public static String getLogLocation()
	{
		return AUTHY_LOG_LOCATION;
	}
	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		OneTouchPersistence.fh.close();
	}

	@Override
	public void contextInitialized(ServletContextEvent arg0) {
		init();
		logger.info("Initialized");
	}
	
	
}
