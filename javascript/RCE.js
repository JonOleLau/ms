const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  const name = req.query.name || 'World';
  res.send(`<h1>Hello, ${name}!</h1>`);
});

app.post('/api/add', (req, res) => {
  const x = req.body.x;
  const y = req.body.y;
  const result = eval(`${x}+${y}`);
  res.send(`<h1>Result: ${result}</h1>`);
});

app.post('/api/execute', (req, res) => {
  const code = req.body.code;
  eval(code);
  res.send('<h1>Code executed successfully!</h1>');
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});