package com.hust.cysec.vtapi;

import java.io.File;

public class FileScan {
	private String filepath;

	public String getFilepath() {
		return filepath;
	}

	public void setFilepath(File filepath) {
		this.filepath = filepath.getAbsolutePath();
	}
}
