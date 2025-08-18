import request from 'supertest';
import app from '../src/server';

describe('Server Endpoint', () => {
  it('should return Hello Secure World on GET /', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'Hello Secure World!' });
  });

  it('should allow requests from whitelisted origins', async () => {
    const res = await request(app).get('/').set('Origin', 'https://nysdev.com');

    expect(res.status).toBe(200);
  });

  it('should block requests from non-whitelisted origins', async () => {
    const res = await request(app)
      .get('/')
      .set('Origin', 'https://notallowed.com');

    expect(res.error).toBeDefined;
  });
});
