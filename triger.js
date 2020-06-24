
Java.perform(function(){
	X=Java.use("class_name");
	Java.scheduleOnMainThread(function(){
		b=X.$new();
        console.log(b.method_name(params));
	})
})