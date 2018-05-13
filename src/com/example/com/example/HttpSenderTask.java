package com.example.com.example;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.BlockingQueue;

/**
 * @program: JnetPcapEx
 * @description:  BlockingQueue中的数据取出来，发送到远端
 * @author: Mr.Wang
 * @create: 2018-03-11 15:58
 **/
public class HttpSenderTask implements Runnable {
    public final static String Tag = "HttpSenderTask";
    private BlockingQueue<String> messageToSend;
    private String url;
    public HttpSenderTask(BlockingQueue<String> messageToSend, String url) {
        this.messageToSend = messageToSend;
        this.url = url;
    }

    @Override
    public void run() {
        while(!Thread.interrupted()) {
            try {
                String message = this.messageToSend.take();
                doStringPost(this.url, message);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
    public static String doStringPost(String urlPath, String message) {
        // HttpClient 6.0被抛弃了
        String result = "";
        BufferedReader reader = null;
        try {
            URL url = new URL(urlPath);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setUseCaches(false);
            conn.setRequestProperty("Connection", "Keep-Alive");
            conn.setRequestProperty("Charset", "UTF-8");
            // 设置文件类型:
            conn.setRequestProperty("Content-Type","application/json; charset=UTF-8");
            // 设置接收类型否则返回415错误
            //conn.setRequestProperty("accept","*/*")此处为暴力方法设置接受所有类型，以此来防范返回415;
            conn.setRequestProperty("accept","application/json");
            // 往服务器里面发送数据
            if (message != null) {
                byte[] writebytes = message.getBytes();
                // 设置文件长度
                conn.setRequestProperty("Content-Length", String.valueOf(writebytes.length));
                OutputStream outwritestream = conn.getOutputStream();
                outwritestream.write(message.getBytes());
                outwritestream.flush();
                outwritestream.close();
                System.out.println("hlhupload : " + "doJsonPost: conn"+conn.getResponseCode());

            }
            if (conn.getResponseCode() == 200) {
                reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()));
                result = reader.readLine();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return result;
    }
}
