package com.hubcitymedia.authycallback.servlets;


import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.hubcitymedia.authycallback.objects.OneTouchPersistence;

/**
 * Servlet implementation class Printer
 */
public class OneTouchPolling	 extends HttpServlet implements ServletContextListener{
	private static final long serialVersionUID = 1L;


	private static Logger logger = Logger.getLogger("PollingLog");
	private static FileHandler fh;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public void init() {
		if(fh == null)
		{
			try {
				fh = new FileHandler(OneTouchPersistence.getLogLocation()+"Polling.log", true);
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
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String uri = request.getRequestURI();

		//Parse the URI request for the uuid
		String[] uriSplit = uri.split("/");
		String uuid = uriSplit[uriSplit.length-1];
		logger.info("Requested UUID=" + uuid);

		//Check to make sure API Key in the request matches what is expected
		String apiKey = request.getHeader("X-Authy-API-Key");
		if(apiKey == null || !apiKey.equals(OneTouchPersistence.getAPIKey()))
		{
			logger.severe("Unexpected API Key received in header \"X-Authy-API-Key\".\n Received: " + apiKey + "\nExpected: " + OneTouchPersistence.getAPIKey());
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		}else
		{
			//Check the persistence map for the callback response status
			String otc = OneTouchPersistence.getCallbackStatus(uuid);
			if(otc != null)
			{
				//If response found, respond with status
				response.setContentType("text/plain");
				PrintWriter out = response.getWriter();
				out.print(otc);
				out.flush();
			}else
			{
				//If no callback response found, return HTTP 204
				response.setStatus(HttpServletResponse.SC_NO_CONTENT);
			}
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
	}

	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		OneTouchPolling.fh.close();
	}

	@Override
	public void contextInitialized(ServletContextEvent arg0) {
		init();
	}
}
