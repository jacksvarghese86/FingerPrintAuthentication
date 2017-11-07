package com.jacksvarghese.fingerprintauthentication;

import android.hardware.fingerprint.FingerprintManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity implements FingerPrintHandler.Listener {

    FingerPrintHandler mFingerPrintHandler;

    private TextView mInstructionsTV;
    private ImageView mIconView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mInstructionsTV = findViewById(R.id.instruction);
        mIconView = findViewById(R.id.finger);

        mFingerPrintHandler = new FingerPrintHandler(getApplicationContext(), this);
        mIconView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                mFingerPrintHandler.startAuth();
                mInstructionsTV.setText(R.string.instructions2);
            }
        });
    }

    @Override
    protected void onDestroy() {
        mFingerPrintHandler.cancel();
        super.onDestroy();
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        mInstructionsTV.setText("onAuthenticationError: "+errString);
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        mInstructionsTV.setText("onAuthenticationHelp: "+helpString);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        mInstructionsTV.setText("onAuthenticationSucceeded");
    }

    @Override
    public void onAuthenticationFailed() {
        mInstructionsTV.setText("onAuthenticationFailed");
    }

    @Override
    public void onNoOSSupport() {
        mIconView.setEnabled(false);
        mInstructionsTV.setText("OS version should be > 23");
    }

    @Override
    public void onNoSensor() {
        mIconView.setEnabled(false);
        mInstructionsTV.setText("Your device doesn't support fingerprint authentication");
    }

    @Override
    public void onNoPermission() {
        mIconView.setEnabled(false);
        mInstructionsTV.setText("Please enable the fingerprint permission");
    }

    @Override
    public void onNoFingerPrints() {
        mIconView.setEnabled(false);
        mInstructionsTV.setText("No fingerprint configured. Please register at least one fingerprint in your device's Settings");
    }

    @Override
    public void onNoLockScreen() {
        mIconView.setEnabled(false);
        mInstructionsTV.setText("Please enable lockscreen security in your device's Settings");
    }

    @Override
    public void onCipherError() {
        mInstructionsTV.setText("Something unexpected");
    }
}
