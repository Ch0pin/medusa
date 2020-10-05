package com.medusa.agent;

import dalvik.system.DexClassLoader;
import android.content.Context;
import android.util.Log;
import android.widget.Toast;


public class JarDex {

    private Context mContext;
    private static DexClassLoader dcl = null;

    public JarDex(Context cntx){
        this.mContext = cntx;
    }


    public void loadClazz(String dexPath, String clazz, String methodName){


        Class nClazz;
        try{
            nClazz = new DexClassLoader(dexPath,mContext.getCodeCacheDir().getAbsolutePath(), null,getClass().getClassLoader()).loadClass(clazz);
            String j = (String) nClazz.getMethod(methodName,new Class[0]).invoke(nClazz.newInstance(), new Object[0]);
            Log.d("ret:",j);
            //Toast.makeText(mContext, (String) nClazz.getMethod("hello", new Class[0]).invoke(nClazz.newInstance(), new Object[0]), 0).show();
        }
        catch (Exception e){
            Toast.makeText(mContext,e.toString(),Toast.LENGTH_LONG);



        }
    }

}
