package com.jacksvarghese.fingerprintauthentication;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v4.app.ActivityCompat;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import static android.content.Context.FINGERPRINT_SERVICE;
import static android.content.Context.KEYGUARD_SERVICE;

/**
 * Created by jacksvarghese on 11/3/17.
 */
public class FingerPrintHandler {

    private static final String TAG = "FingerPrintHandler";

    private static final String KEY_NAME = "YOUR_APP_KEY";

    private Context mContext;
    private Listener mListener;
    private FingerprintManager mFingerprintManager;
    private FingerprintManager.AuthenticationCallback mAuthCallback;
    private FingerprintManager.CryptoObject mCryptoObject;
    private CancellationSignal mCancellationSignal;

    public interface Listener {
        void onAuthenticationError(int errorCode, CharSequence errString);

        void onAuthenticationHelp(int helpCode, CharSequence helpString);

        void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result);

        void onAuthenticationFailed();

        void onNoOSSupport();

        void onNoSensor();

        void onNoPermission();

        void onNoFingerPrints();

        void onNoLockScreen();

        void onCipherError();
    }

    public FingerPrintHandler(Context context, Listener listener) {
        mContext = context;
        mListener = listener;

        // If your app’s minSdkVersion is anything lower than 23, then you have to verify that
        // the device is running Marshmallow or higher before executing any fingerprint-related code
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            //Get an instance of KeyguardManager and FingerprintManager
            KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(KEYGUARD_SERVICE);
            mFingerprintManager = (FingerprintManager) context.getSystemService(FINGERPRINT_SERVICE);

            //Check whether device has a fingerprint sensor
            if (!mFingerprintManager.isHardwareDetected()) {
                // If a fingerprint sensor isn’t available, then inform user that
                // they will be unable to use apps fingerprint functionality
                Log.d(TAG, "no hardware support");
                listener.onNoSensor();
                return;
            }

            //Check whether user has granted the USE_FINGERPRINT permission
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT)
                    != PackageManager.PERMISSION_GRANTED) {
                // If app doesn't have this permission, then notify user
                Log.d(TAG, "no fingerprint permission");
                listener.onNoPermission();
                return;
            }

            //Check user has registered at least one fingerprint
            if (!mFingerprintManager.hasEnrolledFingerprints()) {
                // If user hasn’t configured any fingerprints, then notify user
                Log.d(TAG, "No fingerprint configured");
                listener.onNoFingerPrints();
                return;
            }

            //Check that the lockscreen is secured//
            if (!keyguardManager.isKeyguardSecure()) {
                // If the user hasn’t secured their lockscreen with a PIN password or pattern,
                // then notify user
                Log.d(TAG, "Please enable lockscreen security in your device's Settings");
                listener.onNoLockScreen();
                return;
            }

            //Generate cipher which is required for finger print authentication
            Cipher cipher = generateCipher();
            if (cipher != null) {
                //If the mCipher is initialized successfully, then create a CryptoObject instance
                mCryptoObject = new FingerprintManager.CryptoObject(cipher);
                mAuthCallback = new FingerprintManager.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        Log.e(TAG, "onAuthenticationError");
                        mListener.onAuthenticationError(errorCode, errString);
                    }

                    @Override
                    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                        Log.e(TAG, "onAuthenticationHelp");
                        mListener.onAuthenticationHelp(helpCode, helpString);
                    }

                    @Override
                    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                        Log.e(TAG, "onAuthenticationSucceeded");
                        mListener.onAuthenticationSucceeded(result);
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        Log.e(TAG, "onAuthenticationFailed");
                        mListener.onAuthenticationFailed();
                    }
                };
            } else {
                listener.onCipherError();
            }
        } else {
            listener.onNoOSSupport();
        }

    }

    /**
     * Call this method to enable fingerprint sensor. Sensor will then start listening for fingerprint touch
     */
    public void startAuth() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            //Used later to cancel authentication.
            mCancellationSignal = new CancellationSignal();
            mFingerprintManager.authenticate(mCryptoObject, mCancellationSignal, 0, mAuthCallback, null);
        }
    }

    /**
     * Cancel the finger print sensing.
     */
    public void cancel() {
        if (mCancellationSignal != null) {
            mCancellationSignal.cancel();
        }
    }

    private Cipher generateCipher() {
        try {
            // Obtain a reference to the Standard Keystore
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

            //Generate the key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            //Initialize keystore
            keyStore.load(null);

            //Initialize the KeyGenerator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenerator.init(
                        new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                                //Configure this key so that the user has to confirm their identity with
                                // a fingerprint each time
                                .setUserAuthenticationRequired(true)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                                .build());
            }

            //Generate the key
            SecretKey key = keyGenerator.generateKey();

            //Obtain a mCipher instance and configure it with the properties required for
            // fingerprint authentication
            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher;
        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | InvalidAlgorithmParameterException
                | CertificateException
                | NoSuchPaddingException
                | InvalidKeyException
                | IOException exc) {
            exc.printStackTrace();
            return null;
        }
    }
}
