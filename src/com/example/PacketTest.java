package com.example;

import com.example.com.example.HttpSenderTask;
import com.example.tcpdump.DataFromLog;
import com.example.tcpdump.FeaturesExtratedFromFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;


/**
 * @program: JnetPcapEx
 * @description:
 * @author: Mr.Wang
 * @create: 2018-03-10 09:42
 **/
public class PacketTest {
    public static String url = "http://localhost:80/FlowDataCollector/message";
    public static int capacity = 5;
    private Set<DataFromLog> connSet = null;
    public static void main(String[] args) {
        BlockingQueue<String> messageToSend = new LinkedBlockingQueue<>(capacity);
        FeaturesExtratedFromFile task1 = new FeaturesExtratedFromFile(messageToSend);
        HttpSenderTask task2 = new HttpSenderTask(messageToSend, url);
        ExecutorService exec = Executors.newCachedThreadPool();
        exec.execute(task1);
        for (int i = 0; i < 1; i++) {
            exec.execute(task2);
        }
    }

}
