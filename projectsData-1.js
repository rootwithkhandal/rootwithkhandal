export const projectsData = [
  {
    id: "trustlayer",
    title: "TrustLayer",
    category: "web3ai",
    description: "Automated Web3 Smart Contract Auditing & AI Threat Prevention Engine. Uses static analysis AST parsers and LLM guardrails to detect reentrancy, integer overflows, and front-running vulnerabilities.",
    tags: ["Rust", "Solidity", "Python", "AI Agents", "Static Analysis"],
    github: "https://github.com/rootwithkhandal/TrustLayer",
    stars: 142,
    forks: 28,
    featured: true
  },
  {
    id: "packetforge",
    title: "PacketForge",
    category: "forensics",
    description: "Low-level custom network packet manipulation & PCAP forensic analyzer. Craft raw TCP/IP frames, inject custom payloads, and parse complex multi-gigabyte forensic traffic dumps.",
    tags: ["C++", "pcap", "Linux Kernel", "Rust", "Network Forensics"],
    github: "https://github.com/rootwithkhandal/PacketForge",
    stars: 98,
    forks: 15,
    featured: true
  },
  {
    id: "blackwall",
    title: "Blackwall",
    category: "blueteam",
    description: "Autonomous SOC incident response & threat hunting bot for SIEM systems. Leverages eBPF kernel tracing and Suricata NIDS alerts to isolate compromised hosts within milliseconds.",
    tags: ["Python", "eBPF", "Suricata", "SIEM", "Docker"],
    github: "https://github.com/rootwithkhandal/Blackwall",
    stars: 215,
    forks: 44,
    featured: true
  },
  {
    id: "hexcrypt",
    title: "HexCrypt",
    category: "redteam",
    description: "Hardware-accelerated polymorphic cryptographic payload generator for red team operations. Generates unique shellcode signatures on each execution to test AV/EDR detection limits.",
    tags: ["Assembly x86_64", "C", "Rust", "Cryptography"],
    github: "https://github.com/rootwithkhandal/HexCrypt",
    stars: 176,
    forks: 31,
    featured: true
  },
  {
    id: "hookshield",
    title: "HookShield",
    category: "redteam",
    description: "Kernel-level API hooking & anti-rootkit detection driver. Intercepts Nt* system calls in Windows user-space and kernel-space to identify malicious DLL injection and inline hooks.",
    tags: ["C", "Windows Internals", "Kernel Driver", "C++"],
    github: "https://github.com/rootwithkhandal/HookShield",
    stars: 112,
    forks: 19,
    featured: false
  },
  {
    id: "reconforge",
    title: "ReconForge",
    category: "redteam",
    description: "Automated OSINT & attack surface discovery framework. Performs DNS brute-forcing, certificate transparency log scraping, and port scanning with graph database visualization.",
    tags: ["Go", "GraphDB", "Python", "Shodan API", "OSINT"],
    github: "https://github.com/rootwithkhandal/ReconForge",
    stars: 130,
    forks: 22,
    featured: false
  },
  {
    id: "mcp-firewall",
    title: "mcp-firewall",
    category: "web3ai",
    description: "Model Context Protocol Security Firewall & Prompt Injection Defense. Intercepts tool calls and context payloads between LLM agents and system APIs to enforce zero-trust execution boundaries.",
    tags: ["TypeScript", "Node.js", "MCP", "Security Guardrails"],
    github: "https://github.com/rootwithkhandal/mcp-firewall",
    stars: 189,
    forks: 37,
    featured: true
  }
];
