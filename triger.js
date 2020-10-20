function getContext() {
	return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  }


Java.perform(function(){
    var X=Java.use("");
	Java.scheduleOnMainThread(function(){
        var k = X.ormn(getContext(),2);

        console.log('Ret:'+k);

	})
})

