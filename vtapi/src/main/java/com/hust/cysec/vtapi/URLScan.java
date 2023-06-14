package com.hust.cysec.vtapi;

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
	public void POSTUrl(String apikey, String urlStr) throws IOException, InterruptedException {
		HttpClient client = HttpClient.newBuilder().build();
		
		String urlElement = "url=" + urlStr;
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
		} catch (org.json.JSONException e) {
			System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
	        return;
		}
	}
	
	//get URL report
	public void GETReport(String apikey) throws IOException, InterruptedException {
		if (this.getAnalysisId() == null) return;
		
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/analyses/" + getAnalysisId()))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
		setJson(json);
		//set attributes
		try {
			setName(json.getJSONObject("meta").getJSONObject("url_info").getString("url"));
			setObjectId(json.getJSONObject("meta").getJSONObject("url_info").getString("id"));
			setHarmless(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("harmless"));
			setUndetected(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("undetected"));
			setMalicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("malicious"));
			setSuspicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("suspicious"));
			setTimeout(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("timeout"));
		} catch (org.json.JSONException e) {
			System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
	        return;
		}
		
	}
	
	//print the report and dump to csv file
	public void toCSVReport() {
		System.out.println(">>> URL REPORT SUMMARY <<<");
		if (this.getObjectId() == null || getJson() == null) {
			System.out.println("ERROR: No report found...");
			return;
		}
		System.out.println("> Metadata");
		System.out.println("URL path: " + getName());
		System.out.println("URL identifier: " + getObjectId());
		System.out.println("> Stats");
		System.out.println("Harmless: " + getHarmless());
		System.out.println("Malicious: " + getMalicious());
		System.out.println("Suspicious: " + getSuspicious());
		System.out.println("Undetected: " + getUndetected());
		System.out.println("Timeout: " + getTimeout());
		
		boolean isNewFile = !new File("url_report.csv").exists();
		try (FileWriter writer = new FileWriter("url_report.csv", true)) {
	        // Write header
			if (isNewFile) {
				writer.write("URL path,URL identifier,Harmless,Suspicious,Malicious,Undetected,Timeout\n");
			}

	        // Write data
	        StringBuilder sb = new StringBuilder();
	        sb.append(getName()).append(",")
	                .append(getObjectId()).append(",")
	                .append(getHarmless()).append(",")
	                .append(getSuspicious()).append(",")
	                .append(getMalicious()).append(",")
	                .append(getUndetected()).append(",")
	                .append(getTimeout()).append("\n");

	        writer.write(sb.toString());
	    } catch (IOException e) {
	        System.out.println("ERROR: Failed to write CSV file: " + e.getMessage());
	    }
	}
}
