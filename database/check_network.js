const dns = require("dns").promises;

async function checkDNS(hostname) {
    try {
        const addresses = await dns.resolve(hostname);
        console.log(`✅ Resolved ${hostname} to:`, addresses.join(", "));
        return true;
    } catch (err) {
        console.log(`❌ Failed to resolve ${hostname}: ${err.message}`);
        return false;
    }
}

async function runDiagnostics() {
    console.log("🌐 --- Running Network & DNS Diagnostics ---");
    
    console.log("\n1. Testing general internet DNS resolution:");
    await checkDNS("google.com");
    
    console.log("\n2. Testing Aiven main site DNS resolution:");
    await checkDNS("aiven.io");
    
    console.log("\n3. Testing Aiven cloud infrastructure DNS resolution:");
    await checkDNS("a.aivencloud.com");
    
    console.log("\n4. Testing your specific database host DNS resolution:");
    const dbHost = "mysql-32a54515-pagalamahadeep14-7bc0.a.aivencloud.com";
    const resolved = await checkDNS(dbHost);
    
    console.log("\n-------------------------------------------");
    if (!resolved) {
        console.log("💡 Tip: If other Aiven sites resolve, but your database host does not, your Aiven MySQL service is likely Suspended or Paused.");
        console.log("👉 Go to your Aiven console (https://console.aiven.io/), open your service, and check if there is a 'Resume' button to click.");
    }
}

runDiagnostics();
