package com.medusa.agent;

import android.app.NotificationManager;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;
import android.content.Context;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

public class Receiver extends BroadcastReceiver {
    NotificationManager nm;

    public Receiver(){
        //nm=null;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        //nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

        Bundle bundle = intent.getExtras();

        try{


            Intent intentA = new Intent(context,MainActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            PendingIntent pendingIntent = PendingIntent.getActivity(context, 0, intent, 0);

            String subject = intent.getStringExtra("subject");
            String body = intent.getStringExtra("body");
            String channel = "chan";
            Toast.makeText(context, "Intent received with Body:"+body+ ", Subject:"+subject, Toast.LENGTH_LONG).show();
            NotificationCompat.Builder builder = new NotificationCompat.Builder(context, channel)
                    .setSmallIcon(R.drawable.notificationicon)
                    .setContentTitle(subject)
                    .setContentText(body)
                    .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                    .setContentIntent(pendingIntent)
                    .setAutoCancel(true);

            NotificationManagerCompat notificationManager = NotificationManagerCompat.from(context);
            int id = 332434;
            // notificationId is a unique int for each notification that you must define
            notificationManager.notify(id,builder.build());

        }
        catch(Exception e){
            e.printStackTrace();
        }


    }
}


