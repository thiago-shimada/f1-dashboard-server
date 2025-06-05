const http = require('http');

const options = {
  hostname: '127.0.0.1',
  port: 3001,
  path: '/check-auth',
  method: 'GET',
  timeout: 2000
};

const request = http.request(options, (response) => {
  if (response.statusCode === 200 || response.statusCode === 401) {
    console.log('Health check passed');
    process.exit(0);
  } else {
    console.log(`Health check failed with status: ${response.statusCode}`);
    process.exit(1);
  }
});

request.on('error', (error) => {
  console.log(`Health check failed: ${error.message}`);
  process.exit(1);
});

request.on('timeout', () => {
  console.log('Health check timeout');
  request.destroy();
  process.exit(1);
});

request.end();
