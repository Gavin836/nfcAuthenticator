package com.example.nfcauthenticator;

import androidx.appcompat.app.AppCompatActivity;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SecretScreen extends AppCompatActivity {
    String secret;
    Integer counter;
    final static double passLength = 6;
    Button button;
    TextView password;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secret_screen);

        password = findViewById(R.id.passwordBox);
        secret = getIntent().getStringExtra("secret");
        intialiseCounter();
        try {
            generatePassword();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public void buttonClick(View v) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        generatePassword();
    }

    private void intialiseCounter() {
        SharedPreferences prefs = this.getSharedPreferences(
                "com.example.nfcauthenticator", this.MODE_PRIVATE);

        counter = prefs.getInt("nfcCounter", 0);
    }

    private void updatePrefs(){
        SharedPreferences prefs = this.getSharedPreferences(
                "com.example.nfcauthenticator", this.MODE_PRIVATE);
        prefs.edit().putInt("nfcCounter", counter);
        prefs.edit().apply();
    }

    public void generatePassword() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        password.setText(HOTP().toString());
        counter = counter + 1;
        updatePrefs();
    }

    private Integer HOTP() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] hashed = hmacSha1(secret, counter);
        Integer truncatedHash = dynTrunc(hashed);
        Double finalPass = truncatedHash % Math.pow(10, passLength);

        return Math.abs(finalPass.intValue());
    }

    private Integer dynTrunc(byte[] HS) {
        byte[] offset = new byte[4];

        System.arraycopy(HS,HS.length - 5, offset,0, 4 );

        return ByteBuffer.wrap(offset).getInt();
    }


    /** Andrei Buneyeu
     * https://stackoverflow.com/questions/6026339/how-to-generate-hmac-sha1-signature-in-android
     */
    private static byte[] hmacSha1(String value, Integer key)
            throws UnsupportedEncodingException, NoSuchAlgorithmException,
            InvalidKeyException {
        String type = "HmacSHA1";
        SecretKeySpec secret = new SecretKeySpec(key.toString().getBytes(), type);
        Mac mac = Mac.getInstance(type);
        mac.init(secret);
        byte[] bytes = mac.doFinal(value.getBytes());

        return bytes;
        //return bytesToHex(bytes);
    }
    /**
    private final static char[] hexArray = "0123456789abcdef".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
     **/
}
