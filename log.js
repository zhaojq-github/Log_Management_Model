http = require('http');
cgi  = require('./html/cgi/cgi');

var server = http.createServer(
  cgi(__dirname + '/cgi-bin/test.cgi')
);
server.listen(5555, function() {
  console.log('server listening');
	var options = { 
		hostname: '127.0.0.1', 
		port: 5555, 
		path: '/?test=1', 
		method: 'GET' 
	}; 
  var req = http.request(options);
  req.on('response', function (res) {
    console.log(res.headers);
  });
  req.end();
});
