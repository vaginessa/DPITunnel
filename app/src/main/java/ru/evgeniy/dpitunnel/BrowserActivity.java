package ru.evgeniy.dpitunnel;

import android.annotation.TargetApi;
import android.app.ActivityManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.view.KeyEvent;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import android.widget.Toast;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BrowserActivity extends AppCompatActivity {

    private WebView browserWebview;
    private ImageButton browserBackButton;
    private EditText browserEditText;
    private ProgressBar progressBar;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_browser);

        if(!isServiceRunning(NativeService.class)) {
            Toast.makeText(this, getString(R.string.please_run_service), Toast.LENGTH_SHORT).show();
            finish();
        }

        // Find layout elements
        browserWebview = findViewById(R.id.browser_webview);
        browserBackButton = findViewById(R.id.browser_back_button);
        browserEditText = findViewById(R.id.browser_edit_text);
        progressBar = findViewById(R.id.browser_progress_bar);

        // Initialize buttons
        browserBackButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });

        // Initialize edittext
        browserEditText.setOnKeyListener(new View.OnKeyListener() {
            @Override
            public boolean onKey(View v, int keyCode, KeyEvent event) {
                if ((event.getAction() == KeyEvent.ACTION_DOWN) && (keyCode == KeyEvent.KEYCODE_ENTER)) {

                    // Check if input string is url
                    String urlPattern = "https?://(www.)?[-a-zA-Z0-9@:%._+~#=]{1,256}.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)";
                    if(isStringMatch(browserEditText.getText().toString(), urlPattern)) {
                        browserWebview.loadUrl(browserEditText.getText().toString());
                    } else {
                        browserWebview.loadUrl("https://www.google.com/search?q=" + browserEditText.getText().toString().replace(" ", "+"));
                        browserEditText.setText("https://www.google.com/search?q=" + browserEditText.getText().toString().replace(" ", "+"));
                    }

                    return true;
                }

                return false;
            }
        });

        // Set webview client
        browserWebview.setWebViewClient(new BrowserWebViewClient());

        // Enable zoom
        browserWebview.getSettings().setSupportZoom(true);
        browserWebview.getSettings().setBuiltInZoomControls(true);
        browserWebview.getSettings().setDisplayZoomControls(false);

        // Set DPI Tunnel proxy
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        System.setProperty("http.proxyHost", "127.0.0.1");
        System.setProperty("http.proxyPort", prefs.getString("other_bind_port", "8080"));
        System.setProperty("https.proxyHost", "127.0.0.1");
        System.setProperty("https.proxyPort", prefs.getString("other_bind_port", "8080"));

        // Enable javascript
        browserWebview.getSettings().setJavaScriptEnabled(true);

        // Load start page
        browserWebview.loadUrl("http://google.com");
    }

    private static boolean isStringMatch(String s, String pattern) {
        try {
            Pattern patt = Pattern.compile(pattern);
            Matcher matcher = patt.matcher(s);
            return matcher.matches();
        } catch (RuntimeException e) {
            return false;
        }
    }

    private boolean isServiceRunning(Class<?> serviceClass) {
        ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (serviceClass.getName().equals(service.service.getClassName())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void onBackPressed() {
        if(browserWebview.canGoBack()) {
            browserWebview.goBack();
        } else {
            super.onBackPressed();
        }
    }

    private class BrowserWebViewClient extends WebViewClient {

        // Show progress bar
        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            super.onPageStarted(view, url, favicon);
            progressBar.setVisibility(View.VISIBLE);
            browserEditText.setText(url);
        }

        // For new devices
        @TargetApi(Build.VERSION_CODES.N)
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            view.loadUrl(request.getUrl().toString());
            return true;
        }

        // For old devices
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            view.loadUrl(url);
            return true;
        }

        // Hide progress bar
        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            progressBar.setVisibility(View.GONE);
        }
    }
}
