import express from 'express';
import bodyParser from 'body-parser';

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', (req: express.Request, res: express.Response) => {
  const name = req.query.name || 'World';
  res.send(`<h1>Hello, ${name}!</h1>`);
});

app.post('/api/add', (req: express.Request, res: express.Response) => {
  const x = req.body.x;
  const y = req.body.y;
  const result = eval(`${x}+${y}`);
  res.send(`<h1>Result: ${result}</h1>`);
});

app.post('/api/execute', (req: express.Request, res: express.Response) => {
  const code = req.body.code;
  eval(code);
  res.send('<h1>Code executed successfully!</h1>');
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
