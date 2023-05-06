	package com.example.oopbee.ui;

import com.example.oopbee.business.BeeHive;
import com.example.oopbee.entity.Bee;

import java.util.ArrayList;
import java.util.Scanner;


/**
 * UI Class
 */
public class BeeUI {
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        BeeHive bh = null;
        boolean keepRunning = true;
        Scanner s = new Scanner(System.in);
        int choice;

        while (keepRunning) {
            //menu
            logger.log("--------------Bee hive--------------");
            logger.log("\t1 – Create bee list");
            logger.log("\t2 – Attack bees");
            logger.log("\t3 - Exit");
            logger.log("Enter your choice (1, 2 or 3): ");
            choice = s.nextInt();
            ArrayList<Bee> bees;
            switch (choice) {
                case 1:
                    bh = new BeeHive();
                    bh.init();//create 10 bees
                    bees = bh.getAllBees();
                    logger.log("Bees details at the beginning:");
                    showBees(bees);
                    break;
                case 2:
                    if (bh == null) {
                        logger.log("No bee!");
                    } else {
                        bh.attackBees();//attack bees
                        bees = bh.getAllBees();
                        logger.log("Bees details at the moment:");
                        showBees(bees);
                    }
                    break;
                default:
                    keepRunning = false;
            }
        }

        //close
        s.close();

    }

    public static void showBees(ArrayList<Bee> bees) {
        for (int i = 0; i < bees.size(); i++) {
            //show bee information
            logger.log(bees.get(i));
        }
    }
}
