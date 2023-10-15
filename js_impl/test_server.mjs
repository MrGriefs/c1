import { createServer } from 'node:http';

createServer((req, res) => {
  console.log(req.socket.address());
}).listen(8083)
.on('listening', () => {
  console.log('listening')
});