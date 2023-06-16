package com.hust.cysec.vtapi;

import java.io.FileWriter;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONObject;
import java.util.regex.*;

public class DomainScan extends Scan {
	//Domain input validation
	private static final String DOMAIN_PATTERN = "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+(?:[a-zA-Z]{2,})$";
	private static final Pattern pattern = Pattern.compile(DOMAIN_PATTERN);
	@Override
	public boolean isValid() {
		Matcher matcher = pattern.matcher(getName());
		if (matcher.matches())
			return true;
		else
			setName(null);
		return false;
	}
	
	//get domain report
	public void GETReport(String apikey, String domain) throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/domains/" + domain))
			    .header("accept", "application/json")
			    .header("x-apikey", apikey)
			    .method("GET", HttpRequest.BodyPublishers.noBody())
			    .build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		
		JSONObject json = new JSONObject(response.body());
		setJson(json);
		
		//set attributes
		try {
			setName(json.getJSONObject("data").getString("id"));
			setHarmless(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("harmless"));
			setUndetected(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("undetected"));
			setMalicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("malicious"));
			setSuspicious(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("suspicious"));
			setTimeout(json.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats").getInt("timeout"));
			setTime(json.getJSONObject("data").getJSONObject("attributes").getInt("last_analysis_date"));
			
			printSummary();
		} catch (Exception e) {
			try {
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
			} catch (Exception ee) {
				System.out.println("ERROR: " + e.getMessage());
			}
	    }
	}
	
	//print the result and dump to csv file
	public void toCSVReport() {
		boolean isNewFile = !new File("domain_report.csv").exists();
		try (FileWriter writer = new FileWriter("domain_report.csv", true)) {
	        // Write header
			if (isNewFile) {
				writer.write("Domain,Harmless,Suspicious,Malicious,Undetected,Timeout\n");
			}

	        // Write data
	        StringBuilder sb = new StringBuilder();
	        sb.append(getName()).append(",")
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
	
	@Override
	public void POST(String apikey) throws IOException, InterruptedException {
		return;
	}
}
