const express = require('express')
const {spawn} = require('child_process');

	const app = express()
	const bodyParser = require("body-parser");
	app.use(bodyParser.urlencoded({extended:true}));
	var path = require('path');

	app.get('/', (req, res) => {
	  //res.send('Hello World!')

	    res.sendFile(path.resolve('./web.html'));

	   
	})
	
	
	app.post('/block', (req, res)=>{
	    let ip = req.body.block
	    console.log(ip)
	
	
	    spawn("iptables", [ "-I", "FORWARD", "-s", ip, "-j", "DROP"]);
	    spawn("iptables", [ "-I", "FORWARD", "-d", ip, "-j", "DROP"]);
	    spawn("iptables",["-t", "nat", "-I", "PREROUTING","1",  "-i",  "wlx74da38db1b4f", "-p", "tcp","-s", ip, "--dport", "80", "-j", "DNAT", "--to-destination", "10.42.0.1:9090"]);
	    
	    res.send("<h1>Block success</h1>");
	})
	
	
	app.listen(9091);
	console.log("Start listening!")
