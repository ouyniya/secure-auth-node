/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import express from 'express'

/**
 * Custom modules
 */

import config from './config/index.js';

const app = express()

// ปิด header X-Powered-By
app.disable("x-powered-by");

app.get("/", (req, res) => {
  res.send("Hello Secure World!");
});

app.listen(config.PORT, () => {
    console.log(`Server is running on port: ${config.PORT}`)
})