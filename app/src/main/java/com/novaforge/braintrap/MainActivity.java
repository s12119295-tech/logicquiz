package com.novaforge.braintrap;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import com.android.vending.billing.IInAppBillingService;

import org.json.JSONObject;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

public class MainActivity extends Activity {

    // کلید مایکت. کلید RSA پنل توسعه‌دهنده (رشتهٔ base64 بلند) باید اینجا باشد؛
    // بدون آن تأیید امضای خرید شکست می‌خورد و سکه‌ای اضافه نمی‌شود.
    static final String MYKET_KEY = "8fc18b55-e55a-42f1-af58-5a0e09a272b3";

    static final String MARKET_PKG = "ir.mservices.market";
    static final String BIND_ACTION = "ir.mservices.market.InAppBillingService.BIND";
    static final int RC_BUY = 10001;
    static final int API = 3;

    private WebView web;
    private IInAppBillingService svc;
    private boolean pageLoaded = false, restored = false;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        web = new WebView(this);
        setContentView(web);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);          // localStorage برای ذخیرهٔ سکه‌ها
        s.setAllowFileAccess(false);
        s.setMediaPlaybackRequiresUserGesture(false);
        web.addJavascriptInterface(new Bridge(), "Android");
        web.setWebViewClient(new WebViewClient() {
            @Override public void onPageFinished(WebView v, String url) {
                pageLoaded = true;
                restorePurchases();
            }
        });
        web.loadUrl("file:///android_asset/index.html");

        Intent i = new Intent(BIND_ACTION);
        i.setPackage(MARKET_PKG);
        try { bindService(i, conn, BIND_AUTO_CREATE); } catch (Exception ignored) {}
    }

    private final ServiceConnection conn = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName n, IBinder s) {
            svc = IInAppBillingService.Stub.asInterface(s);
            restorePurchases();
        }
        @Override public void onServiceDisconnected(ComponentName n) { svc = null; }
    };

    class Bridge {
        @JavascriptInterface
        public void buy(final String sku) {
            ui.post(() -> startBuy(sku));
        }
    }

    private void js(boolean ok, String sku, String token, String msg) {
        final String code = "window.onMyketResult&&window.onMyketResult(" + ok + "," + JSONObject.quote(sku == null ? "" : sku)
                + "," + JSONObject.quote(token == null ? "" : token) + "," + JSONObject.quote(msg == null ? "" : msg) + ")";
        ui.post(() -> web.evaluateJavascript(code, null));
    }

    private void startBuy(String sku) {
        if (svc == null) { js(false, sku, null, "مایکت روی گوشی نصب نیست یا متصل نشد"); return; }
        try {
            Bundle r = svc.getBuyIntent(API, getPackageName(), sku, "inapp", "bt");
            if (r.getInt("RESPONSE_CODE", -1) != 0) { js(false, sku, null, "خرید شروع نشد"); return; }
            PendingIntent pi = r.getParcelable("BUY_INTENT");
            startIntentSenderForResult(pi.getIntentSender(), RC_BUY, new Intent(), 0, 0, 0);
        } catch (Exception e) { js(false, sku, null, "خطا در اتصال به مایکت"); }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req != RC_BUY) { super.onActivityResult(req, res, data); return; }
        if (data == null || res != RESULT_OK || data.getIntExtra("RESPONSE_CODE", -1) != 0) {
            js(false, null, null, "پرداخت لغو شد");
            return;
        }
        final String json = data.getStringExtra("INAPP_PURCHASE_DATA");
        final String sig = data.getStringExtra("INAPP_DATA_SIGNATURE");
        handlePurchase(json, sig, true);
    }

    private void restorePurchases() {
        if (restored || svc == null || !pageLoaded) return;
        restored = true;
        new Thread(() -> {
            try {
                Bundle r = svc.getPurchases(API, getPackageName(), "inapp", null);
                if (r.getInt("RESPONSE_CODE", -1) != 0) return;
                ArrayList<String> d = r.getStringArrayList("INAPP_PURCHASE_DATA_LIST");
                ArrayList<String> s = r.getStringArrayList("INAPP_DATA_SIGNATURE_LIST");
                if (d == null || s == null) return;
                for (int i = 0; i < d.size(); i++) handlePurchase(d.get(i), s.get(i), false);
            } catch (Exception ignored) {}
        }).start();
    }

    // اعتبارسنجی امضا ← افزودن سکه در جاوااسکریپت (تکراری‌ها با توکن حذف می‌شوند) ← مصرف خرید
    private void handlePurchase(final String json, final String sig, final boolean showErr) {
        new Thread(() -> {
            try {
                if (json == null || sig == null || !verify(json, sig)) {
                    if (showErr) js(false, null, null, "امضای خرید تأیید نشد (کلید RSA مایکت را بررسی کن)");
                    return;
                }
                JSONObject o = new JSONObject(json);
                if (o.optInt("purchaseState", 0) != 0) return;
                String sku = o.getString("productId"), token = o.getString("purchaseToken");
                js(true, sku, token, "");
                if (svc != null) svc.consumePurchase(API, getPackageName(), token);
            } catch (Exception e) {
                if (showErr) js(false, null, null, "خطا در پردازش خرید");
            }
        }).start();
    }

    private boolean verify(String data, String sig) {
        try {
            PublicKey k = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.decode(MYKET_KEY, Base64.DEFAULT)));
            Signature s = Signature.getInstance("SHA1withRSA");
            s.initVerify(k);
            s.update(data.getBytes("UTF-8"));
            return s.verify(Base64.decode(sig, Base64.DEFAULT));
        } catch (Exception e) { return false; }
    }

    @Override protected void onPause() { super.onPause(); web.onPause(); }
    @Override protected void onResume() { super.onResume(); web.onResume(); }
    @Override protected void onDestroy() {
        super.onDestroy();
        if (svc != null) { try { unbindService(conn); } catch (Exception ignored) {} }
    }
}
