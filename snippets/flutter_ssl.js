colorLog('\n-----------------Loading Module: verify_cert_chain by @Ch0pin -------------\n',{c: Color.Green})

var possibleOffsets = [0x3d38f4,0x3c91e4,0x3ecbf0,0x3ecc00]

for(var i = 0; i < possibleOffsets.length; i++){

    try{

        Interceptor.attach(Module.findBaseAddress('libflutter.so').add(possibleOffsets[i]).add(0x1),{


            onEnter: function(args){
                colorLog('[+] Entering ssl_crypto_x509_session_verify_cert_chain ',{c: Color.Green});

            },
            onLeave: function(retval){
                colorLog('\t[+] Initial Return Value: '+retval,{c: Color.Blue});
                colorLog('\t[+] Returning True ',{c: Color.Red});
                retval.replace(0x1);
            }

        });
    }
    catch(err){
        console.log(err);
    }
}