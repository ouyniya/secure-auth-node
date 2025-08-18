import app from './server';
import config from './config/index';

if (process.env.JEST_WORKER_ID === undefined) {
  app.listen(config.PORT, () => {
    console.log(`Server is running on port: ${config.PORT}`);
  });
}
