package com.hust.cysec.vtapi.objectScan;

import java.io.FileWriter;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONObject;

import java.util.regex.*;

public class IPScan extends Scan {
	//IP Address validation
	private static final String IP_ADDRESS_PATTERN = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
            "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
            "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
            "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$"; 
	private static final Pattern pattern = Pattern.compile(IP_ADDRESS_PATTERN);
	
	@Override
	public boolean isValid() {
		Matcher matcher = pattern.matcher(getName());
		if (matcher.matches())
			return true;
		else
			setName(null);
		return false;
	}
	
	@Override
	public void getReport(String apikey) throws IOException, InterruptedException {
		//GET REPORT req
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/ip_addresses/" + getName()))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
			
		JSONObject json = new JSONObject(response.body());
		setJson(json);
		
		//SET ATTRIBUTES
		try {
			//GET BASIC INFO
			setName(json.getJSONObject("data").getString("id"));
			
			//GET ANALYSIS
			setTime(json.getJSONObject("data").getJSONObject("attributes").getInt("last_analysis_date"));
			setHarmless(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("harmless"));
			setUndetected(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("undetected"));
			setMalicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("malicious"));
			setSuspicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("suspicious"));
			setTimeout(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("timeout"));
		} catch (Exception e) {
			try {
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
			} catch (Exception ee) {
				//check if analysis not finished
				if (e.getMessage().equals("JSONObject[\"last_analysis_date\"] not found."))
					System.out.println("WARNING: No finished analysis found!");
				else
					System.out.println("ERROR: " + e.getMessage());
			}
	    }
	}
}
