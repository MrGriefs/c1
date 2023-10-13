import { createServer } from 'node:http';

createServer((req, res) => {
  console.log(req);
}).listen(8080)
.on('listening', () => {
  console.log('listening')
});