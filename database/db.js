const mysql = require("mysql2");
require("dotenv").config();

// Create connection pool (essential for robust server environments)
const pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "system_siege",
    ssl: (process.env.DB_HOST && process.env.DB_HOST !== "localhost" && process.env.DB_HOST !== "127.0.0.1") ? {
        rejectUnauthorized: false
    } : null,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test connection
pool.getConnection((err, connection) => {
    if (err) {
        console.error("❌ Database Connection Failed:");
        console.error(err);
        return;
    }
    console.log("✅ Connected to Database (Aiven/Local MySQL)");
    connection.release();
});

// Export promise-based pool for modern async/await syntax
const promisePool = pool.promise();

module.exports = {
    pool,
    query: (sql, params) => promisePool.query(sql, params),
    execute: (sql, params) => promisePool.execute(sql, params)
};
