var hashMap = Java.use('java.util.HashMap');
var hashMapNode = Java.use('java.util.HashMap$Node');
var iterator = hashMap.entrySet().iterator();
while(iterator.hasNext()){
	var entry = Java.cast(iterator.next(),hashMapNode);
	console.log(entry.getKey());
	console.log(entry.getValue());
}

// enumerate java.util.HashMap
var hashMap = Java.use('java.util.concurrent.ConcurrentHashMap');
var iterator = hashMap.entrySet().iterator();
while(iterator.hasNext()){
	var entry = Java.cast(iterator.next(),Java.use("java.util.concurrent.ConcurrentHashMap$MapEntry"));
	console.log(entry.getKey());
	console.log(entry.getValue());
}

//enumerate java.util.Set

var iterator=set.iterator();
while (iterator.hasNext()) {
  console.log(iterator.next());
}