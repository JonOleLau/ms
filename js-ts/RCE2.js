const http = require('http');
const url = require('url');
const querystring = require('querystring');

const server = http.createServer((req, res) => {
  const { pathname, query } = url.parse(req.url);
  const { cmd } = querystring.parse(query);
  const result = eval(cmd);

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.write(`<h1>Result:</h1><p>${result}</p>`);
  res.end();
});

server.listen(3000, () => {
  console.log('Server listening on port 3000');
});
