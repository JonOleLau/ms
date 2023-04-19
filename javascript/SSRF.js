const http = require('http');

http.createServer((req, res) => {
  const target = req.url.slice(1);

  if (target.startsWith('http://internal')) {
    http.get(target, (resp) => {
      let data = '';
      resp.on('data', (chunk) => {
        data += chunk;
      });
      resp.on('end', () => {
        res.end(data);
      });
    }).on('error', (err) => {
      console.error('Error: ' + err.message);
      res.end();
    });
  } else {
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(`
      <html>
        <body>
          <form action="/" method="post">
            <label for="url">Enter URL to fetch:</label>
            <input type="text" id="url" name="url" value="">
            <button type="submit">Submit</button>
          </form>
        </body>
      </html>
    `);
  }
}).listen(8080);

console.log('Server running at http://localhost:8080/');