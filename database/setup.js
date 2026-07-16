require("dotenv").config({ path: require("path").join(__dirname, "../.env") });
const mysql = require("mysql2");
const fs = require("fs");
const path = require("path");

const connectionConfig = {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    },
    multipleStatements: true // Allow running schema in blocks
};

console.log("⏳ Connecting to Aiven MySQL at:", connectionConfig.host);

const connection = mysql.createConnection(connectionConfig);

connection.connect((err) => {
    if (err) {
        console.error("❌ Connection failed!");
        console.error(err);
        process.exit(1);
    }
    
    console.log("✅ Successfully connected to Aiven MySQL.");
    
    // Read schema.sql
    const schemaPath = path.join(__dirname, "schema.sql");
    console.log("⏳ Reading database schema from:", schemaPath);
    
    const schemaSql = fs.readFileSync(schemaPath, "utf8");
    
    // Execute SQL schema
    connection.query(schemaSql, (queryErr, results) => {
        if (queryErr) {
            console.error("❌ Failed to initialize database schema!");
            console.error(queryErr);
            connection.end();
            process.exit(1);
        }
        
        console.log("✅ Database schema initialized successfully (all tables verified).");
        connection.end();
        console.log("👋 Disconnected.");
        process.exit(0);
    });
});
