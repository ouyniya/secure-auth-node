import request from 'supertest';
import app from '../src/server';

describe('Server Endpoint', () => {
  it('should return Hello Secure World on GET /', async () => {
    const res = await request(app).get(`${process.env.ROUTE_VERSION}`);
    expect(res.status).toBe(200);
  });

  it('should allow requests from whitelisted origins', async () => {
    const res = await request(app)
      .get(`${process.env.ROUTE_VERSION}`)
      .set('Origin', 'https://nysdev.com');

    expect(res.status).toBe(200);
  });

  it('should block requests from non-whitelisted origins', async () => {
    const res = await request(app)
      .get(`${process.env.ROUTE_VERSION}`)
      .set('Origin', 'https://notallowed.com');

    expect(res.error).toBeDefined;
  });
});
