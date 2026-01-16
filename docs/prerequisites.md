# Prerequisites

The application relies on external malware analysis APIs and an AI module.
To enable these integrations, create a `.env` file (based on `.env.example`) and provide valid API keys:

- VirusTotal API key: https://www.virustotal.com
- OPSWAT MetaDefender API key: https://id.opswat.com/login
- SecureAnnex API key: https://app.secureannex.com/login
- Google Gemini API key (AI module): https://aistudio.google.com/app/api-keys

Make sure all required API keys are inserted before running the system, as several components depend on them.
