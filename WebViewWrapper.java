package com.evgenii.jsevaluator;

import java.io.UnsupportedEncodingException;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.text.Html;
import android.text.TextUtils;
import android.util.Base64;
import android.webkit.WebSettings;
import android.webkit.WebView;

import com.evgenii.jsevaluator.interfaces.CallJavaResultInterface;
import com.evgenii.jsevaluator.interfaces.WebViewWrapperInterface;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;


@SuppressLint("SetJavaScriptEnabled")
public class WebViewWrapper implements WebViewWrapperInterface {
    protected WebView mWebView;

    public WebViewWrapper(Context context, CallJavaResultInterface callJavaResult) {
        mWebView = new WebView(context);
        mWebView.setWillNotDraw(true);
        WebSettings webSettings = mWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setDefaultTextEncodingName("utf-8");
        JavaScriptInterface jsInterface = new JavaScriptInterface(callJavaResult);
        mWebView.addJavascriptInterface(jsInterface, JsEvaluator.JS_NAMESPACE);
    }

    @Override
    public void loadJavaScript(String javascript) {
        try {
            String sanitizedJavascript = sanitizeJavascriptInput(javascript);
            String html = String.format("<html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'; base-uri 'self'; img-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; font-src 'self';\"></head><body><script>%s</script></body></html>", sanitizedJavascript);

            byte[] data = html.getBytes("UTF-8");
            String base64 = Base64.encodeToString(data, Base64.DEFAULT);
            mWebView.loadUrl("data:text/html;charset=utf-8;base64," + base64);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String sanitizeJavascriptInput(String javascript) throws PolicyException {
        Policy policy = Policy.getInstance("antisamy-sqlinjection.xml");
        AntiSamy antiSamy = new AntiSamy();
        return antiSamy.scan(javascript, policy);

    }


    public void destroy() {
        if (mWebView != null) {
            mWebView.removeJavascriptInterface(JsEvaluator.JS_NAMESPACE);
            mWebView.loadUrl("about:blank");
            mWebView.stopLoading();
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
                mWebView.freeMemory();
            }
            mWebView.clearHistory();
            mWebView.removeAllViews();
            mWebView.destroyDrawingCache();
            mWebView.destroy();
            mWebView = null;
        }
    }

    public WebView getWebView() {
        return mWebView;
    }
}
