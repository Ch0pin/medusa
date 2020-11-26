// https://www.jianshu.com/p/4291ee42c412

var class_to_load = Java.use('insert_class_name_here');


	Java.scheduleOnMainThread(function(){ 

    var instance_of_class_to_load = class_to_load.$new();

    return instance_of_class_to_load.function_to_invoke();

  })
