# DV1512-CETRA-Codebase

The fullstack code base for the software security project in DV1512.

The goal of this project is to develop an app that analyzes Chrome extensions, to detect potential malicious behavior.

## System Architecture
High-level view of the system components and their interactions:

![System Architecture](docs/diagrams/architecture.svg)

## Threat Model
Threat modeling made in ThreatDragon for the system:

![Threat Model](docs/diagrams/CetraThreatModel.png)


## Dependencies
- Linux OS (either by default, WSL or a virtual machine)
- Pip installed
- requirements.txt

## Prerequisites
The application relies on external malware analysis APIs and an AI module.
To enable these integrations, create a .env file (based on .env.example) and provide valid API keys:

- VirusTotal API key: https://www.virustotal.com
- OPSWAT MetaDefender API key: https://id.opswat.com/login
- SecureAnnex API key: https://app.secureannex.com/login
- Google Gemini API key (AI module): https://aistudio.google.com/app/api-keys

Make sure all required API keys are inserted before running the system, as several components depend on them.

### Django instructions 

#### Install requirements.txt, in terminal:
``` bash
pip install -r requirements.txt
```

#### Migrate changes to database:
``` bash
python manage.py migrate
```

#### To run the tests, in terminal:
``` bash
python manage.py test
```

#### To create a user run, in terminal: 
``` bash
python manage.py createsuperuser --username=joe --email=joe@example.com
```

#### To run the program, in terminal:
```
python manage.py runserver
```
#### To complete program setup:
- Follow the terminals instructions.
- Bypass password strength validation.
- Open localhost website
- Log in with the user created.


