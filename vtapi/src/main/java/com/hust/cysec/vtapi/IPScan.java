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

public class IPScan extends Scan {
	//IP Address validation
	private static final String IP_ADDRESS_PATTERN = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
            "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
            "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
            "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$"; 
	
	private static final Pattern pattern = Pattern.compile(IP_ADDRESS_PATTERN);
	
	public static boolean isValisIP(String ipAddress) {
		Matcher matcher = pattern.matcher(ipAddress);
		return matcher.matches();
	}
	
	//get IP report
	public void GETReport(String apikey, String ipAddress) throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder()
			    .uri(URI.create("https://www.virustotal.com/api/v3/ip_addresses/" + ipAddress))
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
		} catch (org.json.JSONException e) {
			System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
	        return;
		}
	}
	
	//print the result and dump to csv file
	public void toCSVReport() {
		System.out.println(">>> IP ADDRESS REPORT SUMMARY <<<");
		System.out.println("> Metadata");
		System.out.println("IP: " + getName());
		System.out.println("> Stats");
		System.out.println("Harmless: " + getHarmless());
		System.out.println("Malicious: " + getMalicious());
		System.out.println("Suspicious: " + getSuspicious());
		System.out.println("Undetected: " + getUndetected());
		System.out.println("Timeout: " + getTimeout());
		
		boolean isNewFile = !new File("ip_report.csv").exists();
		try (FileWriter writer = new FileWriter("ip_report.csv", true)) {
	        // Write header
			if (isNewFile) {
				writer.write("IP ,Harmless,Suspicious,Malicious,Undetected,Timeout\n");
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
}
