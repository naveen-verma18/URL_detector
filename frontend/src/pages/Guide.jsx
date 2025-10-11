import React, { useState } from "react";

export default function Guide() {
  const [expandedSection, setExpandedSection] = useState(null);

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const attackTypes = [
    {
      id: "phishing",
      title: "Phishing Attacks",
      icon: "🎣",
      description: "Deceptive attempts to steal sensitive information by impersonating legitimate entities.",
      details: [
        "Attackers create fake websites that mimic legitimate ones (banks, social media, etc.)",
        "URLs often use similar-looking domains with slight misspellings",
        "May use URL shorteners to hide the actual destination",
        "Often delivered via email, SMS, or social media messages"
      ],
      examples: [
        "paypa1.com instead of paypal.com (using '1' instead of 'l')",
        "amaz0n.com instead of amazon.com (using '0' instead of 'o')",
        "micros0ft-security.com (adding extra words to legitimate domains)"
      ],
      prevention: [
        "Always verify the exact URL before entering credentials",
        "Look for HTTPS and valid SSL certificates",
        "Be cautious of urgent or threatening messages",
        "Use password managers that auto-fill only on legitimate sites"
      ]
    },
    {
      id: "sql-injection",
      title: "SQL Injection",
      icon: "💉",
      description: "Malicious SQL code inserted into URL parameters to manipulate databases.",
      details: [
        "Exploits vulnerabilities in web applications that don't properly sanitize input",
        "Can expose, modify, or delete database contents",
        "Attackers inject SQL commands through URL parameters or form fields",
        "Can bypass authentication and access unauthorized data"
      ],
      examples: [
        "example.com/product?id=1' OR '1'='1",
        "example.com/search?q='; DROP TABLE users--",
        "example.com/login?user=admin'--&pass=anything"
      ],
      prevention: [
        "Use parameterized queries and prepared statements",
        "Implement input validation and sanitization",
        "Apply the principle of least privilege for database accounts",
        "Use web application firewalls (WAF)"
      ]
    },
    {
      id: "xss",
      title: "Cross-Site Scripting (XSS)",
      icon: "⚡",
      description: "Injection of malicious scripts into web pages viewed by other users.",
      details: [
        "Attackers inject JavaScript or other client-side scripts",
        "Can steal cookies, session tokens, or other sensitive information",
        "May redirect users to malicious sites",
        "Can modify page content or perform actions on behalf of users"
      ],
      examples: [
        "example.com/search?q=<script>alert('XSS')</script>",
        "example.com/profile?name=<img src=x onerror=alert(1)>",
        "example.com/comment?text=<iframe src='malicious.com'></iframe>"
      ],
      prevention: [
        "Encode all user input before displaying it",
        "Use Content Security Policy (CSP) headers",
        "Validate and sanitize all input on both client and server",
        "Use modern frameworks with built-in XSS protection"
      ]
    },
    {
      id: "open-redirect",
      title: "Open Redirect",
      icon: "↪️",
      description: "Vulnerabilities that allow attackers to redirect users to malicious external sites.",
      details: [
        "Exploits redirect functionality in legitimate websites",
        "Users trust the initial domain but are redirected to malicious sites",
        "Often used in phishing campaigns to bypass security filters",
        "Can be combined with other attacks for greater impact"
      ],
      examples: [
        "trusted-site.com/redirect?url=http://malicious.com",
        "example.com/logout?return=//evil.com",
        "bank.com/login?next=https://fake-bank.com"
      ],
      prevention: [
        "Validate and whitelist redirect destinations",
        "Avoid using user-supplied input for redirects",
        "Use relative URLs instead of absolute URLs when possible",
        "Implement warnings for external redirects"
      ]
    },
    {
      id: "path-traversal",
      title: "Path Traversal",
      icon: "📁",
      description: "Accessing files and directories outside the intended directory structure.",
      details: [
        "Uses special characters like '../' to navigate directory structures",
        "Can expose sensitive files like configuration files or source code",
        "May allow reading system files like /etc/passwd",
        "Can lead to information disclosure or further exploitation"
      ],
      examples: [
        "example.com/download?file=../../../etc/passwd",
        "example.com/view?page=../../../../windows/system32/config/sam",
        "example.com/image?path=../../config/database.yml"
      ],
      prevention: [
        "Validate and sanitize file paths",
        "Use whitelists for allowed files",
        "Implement proper access controls",
        "Avoid using user input directly in file system operations"
      ]
    },
    {
      id: "command-injection",
      title: "Command Injection",
      icon: "⌨️",
      description: "Execution of arbitrary system commands through vulnerable web applications.",
      details: [
        "Exploits applications that pass user input to system shell commands",
        "Can execute any command the web server has permissions for",
        "May lead to complete system compromise",
        "Often combined with other techniques for persistence"
      ],
      examples: [
        "example.com/ping?host=8.8.8.8;cat /etc/passwd",
        "example.com/convert?file=image.jpg|rm -rf /",
        "example.com/backup?name=data`whoami`.tar"
      ],
      prevention: [
        "Avoid calling system commands with user input",
        "Use language-specific APIs instead of shell commands",
        "Implement strict input validation",
        "Run applications with minimal privileges"
      ]
    }
  ];

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {/* Header */}
      <div className="text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-3">URL Attack Guide</h1>
        <p className="text-lg text-gray-600 max-w-3xl mx-auto">
          Learn about common URL-based attacks, how to identify them, and best practices for protection.
        </p>
      </div>

      {/* Introduction */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg shadow-md p-6 border border-blue-200">
        <h2 className="text-2xl font-semibold text-gray-900 mb-3">Why URL Security Matters</h2>
        <p className="text-gray-700 leading-relaxed mb-3">
          URLs are the gateway to web applications and can be exploited in numerous ways. Understanding these 
          attack vectors is crucial for both developers and users to maintain security.
        </p>
        <p className="text-gray-700 leading-relaxed">
          This guide covers the most common URL-based attacks, providing real-world examples and practical 
          prevention strategies to help you stay secure online.
        </p>
      </div>

      {/* Attack Types */}
      <div className="space-y-4">
        {attackTypes.map((attack) => (
          <div key={attack.id} className="bg-white rounded-lg shadow-md overflow-hidden border border-gray-200">
            {/* Attack Header */}
            <button
              onClick={() => toggleSection(attack.id)}
              className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors"
            >
              <div className="flex items-center gap-4">
                <span className="text-3xl">{attack.icon}</span>
                <div className="text-left">
                  <h3 className="text-xl font-semibold text-gray-900">{attack.title}</h3>
                  <p className="text-sm text-gray-600 mt-1">{attack.description}</p>
                </div>
              </div>
              <span className="text-2xl text-gray-400">
                {expandedSection === attack.id ? "−" : "+"}
              </span>
            </button>

            {/* Expanded Content */}
            {expandedSection === attack.id && (
              <div className="px-6 pb-6 space-y-6 border-t border-gray-200 pt-6">
                {/* How It Works */}
                <div>
                  <h4 className="font-semibold text-gray-900 mb-3 text-lg">How It Works</h4>
                  <ul className="space-y-2">
                    {attack.details.map((detail, idx) => (
                      <li key={idx} className="flex gap-2 text-gray-700">
                        <span className="text-blue-600 font-bold">•</span>
                        <span>{detail}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Examples */}
                <div>
                  <h4 className="font-semibold text-gray-900 mb-3 text-lg">Examples</h4>
                  <div className="space-y-2">
                    {attack.examples.map((example, idx) => (
                      <div key={idx} className="bg-gray-50 rounded p-3 border border-gray-200">
                        <code className="text-sm text-red-600 break-all">{example}</code>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Prevention */}
                <div>
                  <h4 className="font-semibold text-gray-900 mb-3 text-lg">Prevention & Best Practices</h4>
                  <ul className="space-y-2">
                    {attack.prevention.map((tip, idx) => (
                      <li key={idx} className="flex gap-2 text-gray-700">
                        <span className="text-green-600 font-bold">✓</span>
                        <span>{tip}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* General Best Practices */}
      <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200">
        <h2 className="text-2xl font-semibold text-gray-900 mb-4">General Security Best Practices</h2>
        <div className="grid md:grid-cols-2 gap-6">
          <div>
            <h3 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
              <span className="text-xl">👤</span>
              For Users
            </h3>
            <ul className="space-y-2 text-gray-700">
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Always verify URLs before clicking</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Use browser security extensions</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Keep software and browsers updated</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Enable two-factor authentication</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Be cautious with shortened URLs</span>
              </li>
            </ul>
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
              <span className="text-xl">👨‍💻</span>
              For Developers
            </h3>
            <ul className="space-y-2 text-gray-700">
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Validate and sanitize all user input</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Use parameterized queries</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Implement proper error handling</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Follow OWASP security guidelines</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-600">•</span>
                <span>Conduct regular security audits</span>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Additional Resources */}
      <div className="bg-gradient-to-r from-purple-50 to-pink-50 rounded-lg shadow-md p-6 border border-purple-200">
        <h2 className="text-2xl font-semibold text-gray-900 mb-3">Learn More</h2>
        <p className="text-gray-700 mb-4">
          For more detailed information about web security and URL-based attacks, check out these resources:
        </p>
        <ul className="space-y-2 text-gray-700">
          <li className="flex gap-2">
            <span className="text-purple-600">→</span>
            <span><strong>OWASP Top 10:</strong> Comprehensive guide to web application security risks</span>
          </li>
          <li className="flex gap-2">
            <span className="text-purple-600">→</span>
            <span><strong>PortSwigger Web Security Academy:</strong> Free online training for security testing</span>
          </li>
          <li className="flex gap-2">
            <span className="text-purple-600">→</span>
            <span><strong>NIST Cybersecurity Framework:</strong> Standards and best practices for security</span>
          </li>
        </ul>
      </div>
    </div>
  );
}
