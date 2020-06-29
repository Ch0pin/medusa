Java.perform(function() {

    var textViewClass = Java.use("android.widget.TextView");
    var String = Java.use("java.lang.String");
   

 
    textViewClass.setText.overload('java.lang.CharSequence').implementation = function (originalTxt) {
        var string_to_send = originalTxt.toString();
        var string_to_recv = "";
        send(string_to_send); // send data to python code
        recv(function (received_json_object) {
            string_to_recv = received_json_object.my_data;
        }).wait(); 
        console.log(string_to_send +" : "+ string_to_recv)
  
        var castTostring = String.$new(string_to_recv);

        return this.setText(castTostring);
 
    }

  
});