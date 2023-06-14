package com.hust.cysec.vtapi;

import java.io.FileWriter;

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
	private int time;
	private JSONObject json;
	
	public void toJSONReport() {
		try (FileWriter out = new FileWriter("REPORT_" + name.replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "_") + "_" + time + ".json")) {
	        out.write(getJson().toString());
	    } catch (Exception e) {
	        e.printStackTrace();
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
	public int getTime() {
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
