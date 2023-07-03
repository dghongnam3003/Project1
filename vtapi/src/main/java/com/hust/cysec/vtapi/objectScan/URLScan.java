package com.hust.cysec.vtapi.objectScan;

import java.io.FileWriter;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONObject;

public class URLScan extends Scan {
	
	//post URL
	@Override
	public void post(String apikey) throws IOException, InterruptedException {
		HttpClient client = HttpClient.newBuilder().build();
		
		String urlElement = "url=" + getName();
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/urls"))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .header("content-type", "application/x-www-form-urlencoded")
			    .method("POST", HttpRequest.BodyPublishers.ofString(urlElement))
			    .build();
		
		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
		try {
			String id = json.getJSONObject("data").getString("id");
			setAnalysisId(id);
			setObjectId(id.split("-")[1]);
		} catch (Exception e) {
			try {
				if (json.getJSONObject("error").getString("code").equals("InvalidArgumentError"))
					System.out.println("ERROR: Invalid URL!\n");
				else
					System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")\n");
			} catch (Exception ee) {
				System.out.println("ERROR: " + e.getMessage());
			}
	    }
	}
	

	@Override
	public void getReport(String apikey) throws IOException, InterruptedException {
		if (getObjectId() == null) return;
		
		//SEND REANALYSE req if already get report before
		if (getJson() != null) { 
			HttpRequest rescan = HttpRequest.newBuilder()
				    .uri(URI.create("https://www.virustotal.com/api/v3/urls/" + getObjectId() + "/analyse"))
				    .header("accept", "application/json")
				    .header("x-apikey", apikey)
				    .method("POST", HttpRequest.BodyPublishers.noBody())
				    .build();
				HttpResponse<String> resp = HttpClient.newHttpClient().send(rescan, HttpResponse.BodyHandlers.ofString());
				JSONObject temp = new JSONObject(resp.body());
			try {
		        this.setAnalysisId(temp.getJSONObject("data").getString("id"));
			} catch (Exception e) {
				try {
			        System.out.println("ERROR: " + temp.getJSONObject("error").getString("message") + " (" + temp.getJSONObject("error").getString("code") + ")");
				} catch (Exception ee) {
					System.out.println("ERROR: " + e.getMessage());
				}
		    }
		}
		
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/urls/" + getObjectId()))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
		setJson(json);
		//set attributes
		try {
			//GET BASIC INFO
			setName(json.getJSONObject("data").getJSONObject("attributes").getString("url"));
			
			//GET ANALYSIS
			setTime(json.getJSONObject("data").getJSONObject("attributes").getInt("last_analysis_date"));
			setHarmless(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("harmless"));
			setUndetected(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("undetected"));
			setMalicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("malicious"));
			setSuspicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("suspicious"));
			setTimeout(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("timeout"));
		} catch (Exception e) {
			try {
				//check if analysis not finished
				if (json.getJSONObject("error").getString("code").equals("NotFoundError"))
					System.out.println("WARNING: No finished analysis found!");
				else
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
