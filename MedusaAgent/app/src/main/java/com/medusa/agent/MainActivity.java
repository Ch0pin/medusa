package com.medusa.agent;

import com.codekidlabs.storagechooser.StorageChooser;
import com.medusa.agent.FilePicker;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.app.Activity;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

import lib.folderpicker.FolderPicker;

public class MainActivity extends AppCompatActivity {
    private JarDex jardexLoader;
    private TextView filePath;
    private Button loadFileButton;
    private Button loadDexButton;
    private File selectedFile;
    private String dexFile="";
    private String className="";
    private String methodName="";

    private static final int FILEPICKER_PERMISSIONS = 1;
    Receiver rec = new Receiver();

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        loadFileButton = (Button)findViewById(R.id.load_file_JarDex);
        loadDexButton = (Button) findViewById(R.id.invoke_Function);
        filePath = (TextView)findViewById(R.id.file_path);
        jardexLoader = new JarDex(getApplicationContext());


        createNotificationChannel();
        //register the notification receiver
        this.registerReceiver(rec,new IntentFilter("com.medusa.NOTIFY"));


        loadFileButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String[] PERMISSIONS = {
                        android.Manifest.permission.READ_EXTERNAL_STORAGE,
                        android.Manifest.permission.WRITE_EXTERNAL_STORAGE
                };

                if (hasPermissions(MainActivity.this, PERMISSIONS)) {
                    Intent intent = new Intent(getApplicationContext(), FilePicker.class);
                    startActivityForResult(intent, 1);
                } else {
                    ActivityCompat.requestPermissions(MainActivity.this, PERMISSIONS, FILEPICKER_PERMISSIONS);
                }
            }
        });

        loadDexButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    dexFile = filePath.getText().toString();
                    className = ((EditText) findViewById(R.id.class_to_load)).getText().toString();
                    methodName = ((EditText) findViewById(R.id.function_to_invoke)).getText().toString();
                    jardexLoader.loadClazz(dexFile, className,methodName);
                }
                catch (Exception e){
                    e.printStackTrace();
                }
            }
        });




    }


    /**
     * Helper method that verifies whether the permissions of a given array are granted or not.
     *
     * @param context
     * @param permissions
     * @return {Boolean}
     */
    public static boolean hasPermissions(Context context, String... permissions) {
        if (context != null && permissions != null) {
            for (String permission : permissions) {
                if (ActivityCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Callback that handles the status of the permissions request.
     *
     * @param requestCode
     * @param permissions
     * @param grantResults
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        switch (requestCode) {
            case FILEPICKER_PERMISSIONS: {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    Toast.makeText(
                            MainActivity.this,
                            "Permission granted! Please click on pick a file once again.",
                            Toast.LENGTH_SHORT
                    ).show();
                } else {
                    Toast.makeText(
                            MainActivity.this,
                            "Permission denied to read your External storage :(",
                            Toast.LENGTH_SHORT
                    ).show();
                }

                return;
            }
        }
    }



    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {

        if(resultCode == RESULT_OK) {

            switch(requestCode) {

                case FILEPICKER_PERMISSIONS:

                    if(data.hasExtra(FilePicker.EXTRA_FILE_PATH)) {

                        selectedFile = new File
                                (data.getStringExtra(FilePicker.EXTRA_FILE_PATH));
                        dexFile=selectedFile.getPath();
                        filePath.setText(dexFile);

                    }
                    break;
            }
        }
    }


    @Override
    protected void onDestroy()  {
        super.onDestroy();
        unregisterReceiver(rec);
    }
    private void createNotificationChannel() {


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = "name";
            String description = "desc";
            int importance = NotificationManager.IMPORTANCE_DEFAULT;
            NotificationChannel channel = new NotificationChannel("chan", name, importance);
            channel.setDescription(description);
            // Register the channel with the system; you can't change the importance
            // or other notification behaviors after this
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }


}
