const axios = require("axios");
const { OpenAI } = require("openai");
require("dotenv").config();

// Analyze security scan findings using OpenAI or Gemini
async function analyzeScanReport(url, vulnerabilities, isDefaced, similarityScore, riskLevel) {
    const geminiKey = process.env.GEMINI_API_KEY;
    const openaiKey = process.env.OPENAI_API_KEY;

    if (!geminiKey && !openaiKey) {
        return `⚠️ AI Security Intelligence Summary Unavailable: No API Key configured. 
Please set GEMINI_API_KEY or OPENAI_API_KEY in your backend/.env file.`;
    }

    const prompt = `You are a Senior Web Security Analyst and Threat Intelligence Assistant. 
Analyze the following security scan results for the monitored digital asset and generate a professional security brief.

### MONITORED ASSET INFO
- Target URL: ${url}
- Content Defacement Status: ${isDefaced ? "COMPROMISED / POTENTIAL DEFACEMENT DETECTED" : "INTEGRITY SECURE"}
- Baseline HTML Similarity Index: ${similarityScore}%
- Aggregate Risk Priority: ${riskLevel.toUpperCase()}

### DETECTED VULNERABILITIES & COMPLIANCE MISSES
${vulnerabilities.length === 0 ? "No immediate security header configuration issues found." : vulnerabilities.map((v, i) => `${i + 1}. [${v.severity.toUpperCase()}] ${v.vulnerability}: ${v.description}`).join("\n")}

### INSTRUCTIONS
Please respond with a structured markdown security report containing:
1. **Threat Assessment & Impact Analysis**: Plain-language description of what these findings imply for the organization (e.g. Clickjacking risk, MITM intercept, SEO/Reputational loss from defacement).
2. **Prioritized Action Plan**: Detailed, developer-ready remediation instructions (such as specific nginx/Apache config blocks for headers, SSL enforcement, or content verification procedures).
3. **AI Risk Classification**: Brief verdict explaining why the site is marked as ${riskLevel.toUpperCase()}.

Keep the summary clear, professional, and actionable. Do not use generic filler.`;

    // 1. Prioritize Gemini API (gemini-2.5-flash) if key is provided
    if (geminiKey) {
        try {
            console.log("Calling Google Gemini API (gemini-2.5-flash)...");
            const response = await axios.post(
                `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
                {
                    contents: [
                        {
                            parts: [
                                { text: prompt }
                            ]
                        }
                    ]
                },
                {
                    headers: { "Content-Type": "application/json" },
                    timeout: 10000
                }
            );

            const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) return text;
            throw new Error("Empty candidate list or response format mismatch");
        } catch (err) {
            console.error("❌ Gemini API failed:", err.response?.data || err.message);
            // Fall back to OpenAI if key is present, otherwise propagate
            if (!openaiKey) {
                throw new Error(`Gemini API Error: ${err.message}`);
            }
        }
    }

    // 2. Fallback or use OpenAI if key is provided
    if (openaiKey) {
        try {
            console.log("Calling OpenAI API...");
            const openai = new OpenAI({ apiKey: openaiKey });
            const completion = await openai.chat.completions.create({
                model: "gpt-4-turbo",
                messages: [
                    { role: "system", content: "You are a cyber security auditor assistant." },
                    { role: "user", content: prompt }
                ],
                max_tokens: 1200,
                temperature: 0.2
            });

            return completion.choices[0]?.message?.content || "No summary returned from OpenAI.";
        } catch (err) {
            console.error("❌ OpenAI API failed:", err.message);
            throw new Error(`OpenAI API Error: ${err.message}`);
        }
    }

    return "AI Threat Analysis failed to initialize.";
}

module.exports = {
    analyzeScanReport
};
