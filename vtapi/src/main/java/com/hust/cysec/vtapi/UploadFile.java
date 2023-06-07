package com.hust.cysec.vtapi;

import java.io.File;
import javax.swing.JFileChooser;

import javax.swing.JFrame;

public class UploadFile {
    private JFrame frame;
    
    public UploadFile() {
        frame = new JFrame();

        frame.setVisible(true);
        BringToFront();
    }
    public File getFile() {
        JFileChooser fc = new JFileChooser();
        if(JFileChooser.APPROVE_OPTION == fc.showOpenDialog(null)){
            frame.setVisible(false);
            return fc.getSelectedFile();
        }else {
        	frame.setVisible(false);
            return null;
        }
    }

    private void BringToFront() {                  
                    frame.setExtendedState(JFrame.ICONIFIED);
            frame.setExtendedState(JFrame.NORMAL);

    }

}
