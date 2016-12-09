package com.hubcitymedia.authycallback.servlets;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.hubcitymedia.authycallback.objects.OneTouchPersistence;

import org.apache.tomcat.util.codec.binary.Base64;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

/**
 * Servlet implementation class Printer
 */
public class OneTouchCallback	 extends HttpServlet implements ServletContextListener{
	private static final long serialVersionUID = 1L;


	private static Logger logger = Logger.getLogger("CallbackLog");
	private static FileHandler fh;
	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public void init() {
		if(fh == null)
		{
			try {
				fh = new FileHandler(OneTouchPersistence.getLogLocation()+"Callback.log", true);
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
		String url = request.getRequestURL().toString();
		String method = "GET";
		String queryString = request.getQueryString(); //QueryString is already in sorted case-sensitive alphabetical order
		String nonce = request.getHeader("X-Authy-Signature-Nonce");
		String signature = request.getHeader("X-Authy-Signature");
		try {
			if(validCallback(url, method, queryString, nonce, signature))
			{
				String uuid = request.getParameter("uuid");
				String status = request.getParameter("status");
				OneTouchPersistence.putCallbackStatus(uuid, status);
				logger.info("Inserted UUID="+uuid);
			}
		} catch (InvalidKeyException e) {
			logger.severe("Validation of Authy Signature failed.\nCause:" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.severe("Validation of Authy Signature failed.\nCause:" + e.getMessage());
		}
		
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {		
		String url = request.getRequestURL().toString();
		String method = "POST";
		String params = "";
		String nonce = request.getHeader("X-Authy-Signature-Nonce");
		String signature = request.getHeader("X-Authy-Signature");
		
		try {
			if(validCallback(url, method, params, nonce, signature))
			{
				//Insert into map
				StringBuilder buffer = new StringBuilder();
				BufferedReader reader = request.getReader();
				String line;
				while ((line = reader.readLine()) != null)
				{
					buffer.append(line);
				}
				reader.close();

				String body = buffer.toString();

				JsonElement root = new JsonParser().parse(body);
				String uuid = root.getAsJsonObject().get("uuid").getAsString();
				String status = root.getAsJsonObject().get("status").getAsString();
				OneTouchPersistence.putCallbackStatus(uuid,status);
				logger.info("Inserted status with UUID="+uuid);
			}
		} catch (InvalidKeyException e) {
			logger.severe("Validation of Authy Signature failed.\nCause:" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			logger.severe("Validation of Authy Signature failed.\nCause:" + e.getMessage());
		}
	}

	private boolean validCallback(String url, String method, String queryParams, String nonce, String signature) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException
	{
		String completeToken = nonce+"|"+method+"|"+url+"|"+queryParams; //Create validation token for hashing
		
		//Generate hash based on Authy API Key
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret_key = new SecretKeySpec(OneTouchPersistence.getAPIKey().getBytes(), "HmacSHA256");
		sha256_HMAC.init(secret_key);
		String hash = Base64.encodeBase64String(sha256_HMAC.doFinal(completeToken.getBytes()));
		return hash.equals(signature);
	}

	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		OneTouchCallback.fh.close();
	}

	@Override
	public void contextInitialized(ServletContextEvent arg0) {
		init();
	}

}
