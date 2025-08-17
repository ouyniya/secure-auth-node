/**
 * @copyright 2025 nysdev
 * @license Apache-2.0
 */

/**
 * Node Modules
 */

import express from 'express'

const app = express()

// ปิด header X-Powered-By
app.disable("x-powered-by");

app.get("/", (req, res) => {
  res.send("Hello Secure World!");
});

const PORT = 3000
app.listen(PORT, () => {
    console.log(`Server is running on port: ${PORT}`)
})