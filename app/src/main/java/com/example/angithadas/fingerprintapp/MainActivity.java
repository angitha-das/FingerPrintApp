package com.example.angithadas.fingerprintapp;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {
    private TextView     messageTextView;
    private ImageView    fingerPrintImageView;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    // Variable used for storing the key in the Android Keystore container
    private static final String KEY_NAME = "OverrideAndroid";
    private FingerprintManager fingerprintManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        messageTextView = (TextView) findViewById(R.id.textView);
        fingerPrintImageView = (ImageView) findViewById(R.id.imageViewFinger);

        if (checkFingerPrintSensor()) {
            generateKey();
            Cipher cipher = generateCipher();
            if (cipher != null) {
                //If the cipher is initialized successfully, then
                // create a CryptoObject instance//
                FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
                CancellationSignal cancellationSignal = new CancellationSignal();
                if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                    return;
                }
                fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, authenticationCallback, null);
            }
        }



    }
   FingerprintManager.AuthenticationCallback authenticationCallback =new FingerprintManager.AuthenticationCallback() {
       @Override
       public void onAuthenticationError(int errorCode, CharSequence errString) {
           super.onAuthenticationError(errorCode, errString);
       }

       @Override
       public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
           super.onAuthenticationHelp(helpCode, helpString);
       }

       @Override
       public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
           super.onAuthenticationSucceeded(result);
           showAuthSucceededMessage();
       }

       @Override
       public void onAuthenticationFailed() {
           super.onAuthenticationFailed();
           showAuthFailedMessage();
       }
   };
    public boolean checkFingerPrintSensor() {
        // Initializing both Android Keyguard Manager and Fingerprint Manager
        KeyguardManager keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
        try {
            // Check if the fingerprint sensor is present
            if (!fingerprintManager.isHardwareDetected()) {
                // Update the UI with a message
                messageTextView.setText("Fingerprint authentication not supported");
                return false;
            }
            if (!fingerprintManager.hasEnrolledFingerprints()) {
                messageTextView.setText("No fingerprint configured.");
                return false;
            }
            if (!keyguardManager.isKeyguardSecure()) {
                messageTextView.setText("Secure lock screen not enabled");
                return false;
            }
        } catch (SecurityException se) {
            se.printStackTrace();
        }
        return true;

    }

    public void showAuthSucceededMessage() {
        fingerPrintImageView.setImageResource(R.drawable.ic_fingerprint_green_500_48dp);
        messageTextView.setText("Authentication succeeded.");
    }

    public void showAuthFailedMessage() {
        fingerPrintImageView.setImageResource(R.drawable.ic_fingerprint_red_500_48dp);
        messageTextView.setText("Authentication failed.");
    }

    @TargetApi(Build.VERSION_CODES.M)
    public void generateKey() {
        // Obtain a reference to the Keystore using the standard Android keystore container identifier (“AndroidKeystore”)//
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        // Key generator to generate the key
        try {
            //Initialize an empty KeyStore//
            keyStore.load(null);
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | CertificateException | IOException e) {
            e.printStackTrace();
        }
        //Specify the operation(s) this key can be used for//
        KeyGenParameterSpec keyGenParameterSpec = new
                KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT
                | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                //Configure this key so that the user has to confirm their identity with a fingerprint each time they want to use it//
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();
        try {
            keyGenerator.init(keyGenParameterSpec);
            //Generate the key//
            keyGenerator.generateKey();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    public Cipher generateCipher() {
        Cipher cipher = null;
        //Obtain a cipher instance and configure it with the properties required for fingerprint authentication//
        try {
            cipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/" +
                            KeyProperties.BLOCK_MODE_CBC + "/" +
                            KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            keyStore.load(null);
            Key key = keyStore.getKey(KEY_NAME, null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (KeyStoreException | NoSuchAlgorithmException
                | UnrecoverableKeyException | InvalidKeyException
                | CertificateException | IOException e) {
            e.printStackTrace();
        }
        return cipher;
    }
}
