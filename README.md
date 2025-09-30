# DV1512-CETRA-Codebase

The fullstack code base for the software security project in DV1512.

The goal of this project is to develop an app that analyzes Chrome extensions to detect potential malicious behavior.

## System Architecture
High-level view of the system components and their interactions:

![System Architecture](docs/diagrams/architecture.svg)


### Django instructions 

#### To run the program 
```
python manage.py 
```

#### To run the tests 
``` bash
pyton manage.py test
```

#### To create a a user run 
``` bash
python manage.py createsuperuser --username=joe --email=joe@example.com
```

- Follow the cli instruction
- Bypass password strenth validation
- Log in with that user (duh)


