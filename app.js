const express = require('express');
const app = express();

const PORT = 80;

app.get('/heartbeat', (_, res) => {
  const timestamp = Date.now();
  res.send(`${timestamp}`)
});

app.listen(PORT, () => {
  console.info(`Listening on port ${PORT}`);
})
