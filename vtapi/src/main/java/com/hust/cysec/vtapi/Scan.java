package com.hust.cysec.vtapi;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.json.JSONObject;

public abstract class Scan {
	private String name = null;
	private String objectId = null;
	private String analysisId = null;
	private int harmless;
	private int suspicious;
	private int timeout;
	private int malicious;
	private int undetected;
	private long time;
	private JSONObject json = null;
	
	public void POST(String apikey) throws IOException, InterruptedException {
		//POST info and save report IDs
		objectId = null;
		analysisId = null;
	}
	
	public void GETReport(String apikey) throws IOException, InterruptedException {
		//GET json report and save json + summary stats
		json = null;
		harmless = 0;
		suspicious = 0;
		timeout = 0;
		malicious = 0;
		undetected = 0;
		time = 0;
	}
	
	public void printSummary() {
		System.out.println(">>> REPORT SUMMARY <<<");
		System.out.println("> Info");
		System.out.println("Name: " + name);
		System.out.println("ID: " + objectId);
		DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
		System.out.println("Time: " + dateformat.format(Instant.ofEpochSecond(time)));
		System.out.println("> Analysis stats");
		System.out.println("Harmless: " + harmless);
		System.out.println("Malicious: " + malicious);
		System.out.println("Suspicious: " + suspicious);
		System.out.println("Undetected: " + undetected);
		System.out.println("Timeout: " + timeout);
	}
	
	public void toJSONReport() {
		try (FileWriter out = new FileWriter("REPORT_" + name.replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "_") + "_" + time + ".json")) {
	        out.write(getJson().toString());
		} catch (Exception e) {
			try {
		        System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
			} catch (Exception ee) {
				System.out.println("ERROR: " + e.getMessage());
			}
	    }
	}
	
	public void toCSVReport() {
		System.out.println(">>> REPORT SUMMARY <<<");
		if (this.getObjectId() == null || getJson() == null) {
			System.out.println("ERROR: No report found...");
			return;
		}
		boolean isNewFile = !new File("report.csv").exists();
		try (FileWriter writer = new FileWriter("report.csv", true)) {
			if (isNewFile) {
				writer.write("Name,ID,Harmless,Suspicious,Malicious,Undetected,Timeout\n");
			}
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

	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getObjectId() {
		return objectId;
	}
	public void setObjectId(String id) {
		this.objectId = id;
	}
	public int getHarmless() {
		return harmless;
	}
	public void setHarmless(int harmless) {
		this.harmless = harmless;
	}
	public int getSuspicious() {
		return suspicious;
	}
	public void setSuspicious(int suspicious) {
		this.suspicious = suspicious;
	}
	public int getTimeout() {
		return timeout;
	}
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}
	public int getMalicious() {
		return malicious;
	}
	public void setMalicious(int malicious) {
		this.malicious = malicious;
	}
	public int getUndetected() {
		return undetected;
	}
	public void setUndetected(int undetected) {
		this.undetected = undetected;
	}
	public JSONObject getJson() {
		return json;
	}
	public void setJson(JSONObject json) {
		this.json = json;
	}
	public long getTime() {
		return time;
	}
	public void setTime(int time) {
		this.time = time;
	}
	public String getAnalysisId() {
		return analysisId;
	}
	public void setAnalysisId(String analysisId) {
		this.analysisId = analysisId;
	}
	
	
	
	
}
