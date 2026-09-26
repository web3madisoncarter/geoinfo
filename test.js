const express = require('express');
const app = express();
const port = 6666;

app.get('/', (req, res) => {
  console.log(req);
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});