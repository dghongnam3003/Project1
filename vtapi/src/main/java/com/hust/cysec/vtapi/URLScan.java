package com.hust.cysec.vtapi;

import java.io.FileWriter;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONObject;

public class URLScan {
	private String url = null;
	private String id = null;
	private String identifier = null;
	private int harmless, malicious, suspicious, undetected, timeout;
	
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
			this.id = id;
		} catch (org.json.JSONException e) {
			System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
	        return;
		}
	}
	
	//get URL report
	public void GETUrlReport(String apikey) throws IOException, InterruptedException {
		if (this.id == null) return;
		
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/analyses/" + this.id))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		JSONObject json = new JSONObject(response.body());
		//set attributes
		try {
			this.url = json.getJSONObject("meta").getJSONObject("url_info").getString("url");
			this.identifier = json.getJSONObject("meta").getJSONObject("url_info").getString("id");
			this.harmless = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("harmless");
			this.undetected = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("undetected");
			this.malicious = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("malicious");
			this.suspicious = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("suspicious");
			this.timeout = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats").getInt("timeout");
		} catch (org.json.JSONException e) {
			System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
	        return;
		}
		
	}
	
	//print the report and dump to csv file
	public void printReport() {
		System.out.println(">>> URL REPORT SUMMARY <<<");
		if (this.id == null || this.identifier == null) {
			System.out.println("ERROR: No report found...");
			return;
		}
		System.out.println("> Metadata");
		System.out.println("URL path: " + url);
		System.out.println("URL identifier: " + identifier);
		System.out.println("> Stats");
		System.out.println("Harmless: " + harmless);
		System.out.println("Malicious: " + malicious);
		System.out.println("Suspicious: " + suspicious);
		System.out.println("Undetected: " + undetected);
		System.out.println("Timeout: " + timeout);
		
		boolean isNewFile = !new File("url_report.csv").exists();
		try (FileWriter writer = new FileWriter("url_report.csv", true)) {
	        // Write header
			if (isNewFile) {
				writer.write("URL path,URL identifier,Harmless,Suspicious,Malicious,Undetected,Timeout\n");
			}

	        // Write data
	        StringBuilder sb = new StringBuilder();
	        sb.append(url).append(",")
	                .append(identifier).append(",")
	                .append(harmless).append(",")
	                .append(suspicious).append(",")
	                .append(malicious).append(",")
	                .append(undetected).append(",")
	                .append(timeout).append("\n");

	        writer.write(sb.toString());
	    } catch (IOException e) {
	        System.out.println("ERROR: Failed to write CSV file: " + e.getMessage());
	    }
	}

	public String getUrl() {
		return url;
	}

	public String getId() {
		return id;
	}

	public String getIdentifier() {
		return identifier;
	}

	public int getHarmless() {
		return harmless;
	}

	public int getMalicious() {
		return malicious;
	}

	public int getSuspicious() {
		return suspicious;
	}

	public int getUndetected() {
		return undetected;
	}

	public int getTimeout() {
		return timeout;
	}
}
