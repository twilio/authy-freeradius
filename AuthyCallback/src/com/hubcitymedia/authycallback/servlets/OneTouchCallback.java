package com.hubcitymedia.authycallback.servlets;


import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.hubcitymedia.authycallback.objects.OneTouchPersistence;

import javax.xml.bind.DatatypeConverter;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

/**
 * Servlet implementation class Printer
 */
public class OneTouchCallback	 extends HttpServlet implements ServletContextListener{
	private static final long serialVersionUID = 1L;

	private static Logger logger = Logger.getLogger("CallbackLog");
	private static FileHandler fh;
	private static JsonParser jsonParser = new JsonParser();

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public void init() {
		if(fh == null)
		{
			try {
				fh = new FileHandler(OneTouchPersistence.getLogLocation()+"Callback.log", true);
				fh.setFormatter(new SimpleFormatter());
			} catch (SecurityException | IOException e) {
				e.printStackTrace();
				throw new RuntimeException(e);
			}
			logger.addHandler(fh);
		}
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String uuid = request.getParameter("uuid");
		String status = request.getParameter("status");
		if (uuid == null || status == null) {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			return;
		}

		try {
			handleRequest(request, response, request.getQueryString(), uuid, status);
		} catch (Exception ex) {
			logger.log(Level.SEVERE, "Failed to handle callback request", ex);
			throw ex;
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		JsonObject requestData = readJsonObject(request.getReader());
		JsonElement uuidElement = requestData.get("uuid");
		JsonElement statusElement = requestData.get("status");
		if (uuidElement == null || !uuidElement.isJsonPrimitive()
				|| statusElement == null || !statusElement.isJsonPrimitive())
		{
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			return;
		}

		String uuid = uuidElement.getAsString();
		String status = statusElement.getAsString();
		try {
			handleRequest(request, response, generateParamString(requestData), uuid, status);
		} catch (Exception ex) {
			logger.log(Level.SEVERE, "Failed to handle callback request", ex);
			throw ex;
		}
	}

	private void handleRequest(HttpServletRequest request, HttpServletResponse response, String paramString,
			String uuid, String status)
			throws ServletException, IOException
	{
		String url = request.getRequestURL().toString();
		String method = request.getMethod();
		String nonce = request.getHeader("X-Authy-Signature-Nonce");
		String signature = request.getHeader("X-Authy-Signature");
		try {
			if(validCallback(url, method, paramString, nonce, signature))
			{
				OneTouchPersistence.putCallbackStatus(uuid, status);
				logger.info("Inserted UUID="+uuid);
			}
			else
			{
				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE, "Validation of Authy Signature failed", e);
		}
	}

	private JsonObject readJsonObject(BufferedReader reader) throws IOException {
		// Read the JSON data.
		StringBuilder jsonBuilder = new StringBuilder();
		for (String line = reader.readLine(); line != null; line = reader.readLine()) {
			if (jsonBuilder.length() > 0) {
				jsonBuilder.append('\n');
			}
			jsonBuilder.append(line);
		}

		// Parse the JSON object.
		String jsonString = jsonBuilder.toString();
		JsonElement jsonElement = new JsonParser().parse(jsonString);
		if (!jsonElement.isJsonObject()) {
			String elementType;
			if (jsonElement.isJsonArray()) {
				elementType = "an array";
			} else if (jsonElement.isJsonPrimitive()) {
				elementType = "a primitive value";
			} else { // null
				elementType = "null";
			}
			throw new IOException(String.format("Expected a JSON object, but got %s", elementType));
		}

		return jsonElement.getAsJsonObject();
	}

	private String generateParamString(JsonObject responseData) throws IOException {
		// Flatten the object into a parameter map.
		Map<String, String> flatResponseData = new TreeMap<>();
		flattenRootObject(responseData, flatResponseData);

		// Build the parameter "query string".
		StringBuilder paramStringBuilder = new StringBuilder();
		for (Map.Entry<String, String> param : flatResponseData.entrySet()) {
			if (paramStringBuilder.length() > 0) {
				paramStringBuilder.append("&");
			}
			paramStringBuilder.append(param.getKey()).append("=").append(param.getValue());
		}

		return paramStringBuilder.toString();
	}

	private static void flattenRootObject(JsonObject object, Map<String, String> output) {
		flattenObject(null, object, output);
	}

	private static void flattenObject(String path, JsonObject object, Map<String, String> output) {
		for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
			String propertyName = entry.getKey();
			String propertyPath = path != null
					? String.format("%s%%5B%s%%5D", path, urlEncode(propertyName)) // <path>[<name>]
					: propertyName;
			flattenElement(propertyPath, entry.getValue(), output);
		}
	}

	private static void flattenArray(String path, JsonArray array, Map<String, String> output) {
		for (int elementIndex = 0; elementIndex < array.size(); ++elementIndex) {
			String elementPath = String.format("%s%%5B%d%%5D", path, elementIndex); // <path>[<index>]
			flattenElement(elementPath, array.get(elementIndex), output);
		}
	}

	private static void flattenElement(String elementPath, JsonElement element, Map<String, String> output) {
		if (element.isJsonObject()) {
			flattenObject(elementPath, element.getAsJsonObject(), output);
		} else if (element.isJsonArray()) {
			flattenArray(elementPath, element.getAsJsonArray(), output);
		} else if (element.isJsonPrimitive()) {
			output.put(elementPath, urlEncode(element.getAsString()));
		} else if (element.isJsonNull()) {
			output.put(elementPath, "");
		} else {
			throw new AssertionError("Invalid JSON element: " + element);
		}
	}

	private static String urlEncode(String raw) {
		try {
			return URLEncoder.encode(raw, "UTF-8");
		} catch (UnsupportedEncodingException ex) {
			throw new AssertionError("Huh? No UTF-8??");
		}
	}

	private boolean validCallback(String url, String method, String paramString, String nonce, String signature) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException
	{
		String completeToken = nonce+"|"+method+"|"+url+"|"+paramString; //Create validation token for hashing
		
		//Generate hash based on Authy API Key
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret_key = new SecretKeySpec(OneTouchPersistence.getAPIKey().getBytes(), "HmacSHA256");
		sha256_HMAC.init(secret_key);
		String hash = DatatypeConverter.printBase64Binary(sha256_HMAC.doFinal(completeToken.getBytes()));
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
