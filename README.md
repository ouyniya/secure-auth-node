# My Secure Node.js App

This is a Secure Node.js application built with **TypeScript** and **Express**, packaged with **Docker** for easy development and deployment.

## Scripts

 `npm run build`  Compile TypeScript to `dist/` 

 `npm run dev`  Run dev server (compile then run `dist`) 

 `npm run dev:tsnode`  Run dev server with `ts-node` and live reload 

 `npm run test`  Run tests with Jest 

 `npm run test:coverage`  Run tests with coverage report 


## Docker

### Build Image

```bash
docker build -t my-node-app .
```

### Run Container (Production)

```bash
docker run -p 3001:3000 --name my-node-container --env-file .env my-node-app
```

### Stop & Remove Container

```bash
docker stop my-node-container
docker rm my-node-container
```

## Multi-stage Build Explanation
Stage 1 (builder): Build TypeScript to `dist/`

Stage 2 (production): Copy only `dist` and production dependencies for smaller image


## Environment Variable
```bash
PORT=3000
NODE_ENV=production
```
