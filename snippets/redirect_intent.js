var activity_class_3203948 = Java.use('android.app.Activity');

activity_class_3203948.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function(intent, bundle){
   colorLog('\nA_Redireection'+this+' ====> startActivity(' + intent + ')', {c:Color.Purple});  
   var component = intent.getComponent();
   if (component !== null) {
       var className = component.getClassName();
       if (className === "DESTINATION") {
           intent.setClassName("NEW_D_ESTINATION_PACKAGE", "NEW_DESTINAT_ION_ACTIVITY");
       }
   }
   console.log('Options:'+bundle)
   dumpIntent(intent);   
   colorLog('[^] -------------------------------------------------------------------------------- [^]',{c:Color.Purple});     
   this.startActivity(intent, bundle);
}          