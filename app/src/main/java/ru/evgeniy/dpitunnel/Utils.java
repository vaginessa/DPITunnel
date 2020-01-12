package ru.evgeniy.dpitunnel;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

public class Utils {

    public static String makeDOHRequest(String doh_server, String hostname)
    {
        String response = "";
        try {
            System.setProperty("http.keepAlive", "false");
            System.setProperty("java.net.preferIPv4Stack" , "true");
            URL url = new URL(doh_server + "/dns-query?name=" + hostname + "&type=A");
            HttpsURLConnection c = (HttpsURLConnection) url.openConnection();

            // Add header
            c.setRequestProperty("accept", "application/dns-json");

            // Create the SSL connection
            SSLContext sc;
            sc = SSLContext.getInstance("TLS");
            sc.init(null, null, new java.security.SecureRandom());
            c.setSSLSocketFactory(sc.getSocketFactory());

            // Set options and connect
            c.setReadTimeout(700);
            c.setConnectTimeout(700);
            c.setRequestMethod("GET");
            c.setDoInput(true);

            // Save to string
            InputStream in = c.getInputStream();

            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = in.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }

            response = result.toString("UTF-8");

        } catch (Exception e) {
            Log.e("Java/Utils/makeDOHReqst", "DoH request failed");
            e.printStackTrace();
        }

        return response;
    }
}
