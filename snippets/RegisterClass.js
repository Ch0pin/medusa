// https://www.jianshu.com/p/4291ee42c412

var cls_run = Java.registerClass({

//add the class name 
    name:"class_name",
    implements:[Java.use("java.lang.Runnable")],


//Add the class fields 

    fields:{
        description: 'java.lang.String',
        limit: 'int'
    },


//Add methods 

    methods:{
        run:function(){
            Java.use("android.widget.Toast").makeText(cls_main,Java.use("java.lang.String").$new("this is a test Toast"),1).show()
        
        },
        add:[{
            returnType:'java.lang.String',
            argumentTypes:['java.lang.String','java.lang.String'],
            implementation:function(str1,str2){
                return str1+"+++"+str2
            }
        },
        {
            returnType:'java.lang.String',
            argumentTypes:['java.lang.String'],
            implementation:function(str1){
                return str1+"==="
            }
        }
        ]
    }
})