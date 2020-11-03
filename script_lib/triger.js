function getContext() {
	return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  }

Java.perform(function() {

  var _xclass=Java.use("dot.android.foo");
	Java.scheduleOnMainThread(function(){
    var x_instance = _xclass.$new();

    x_instance.a_func();

  })
  



});
