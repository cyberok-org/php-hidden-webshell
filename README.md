## How to protect from fileless web shells

Materials from the speech "How to protect yourself from hidden web shells".
Repository structure:
- "dev/files" directory -- contains PHP extenstion source-code and shell-code extractor script
- "dev/generate.sh" -- script for creating and building PHP extension
- "docker/etc" directory -- contains PHP/httpd config files and web-shell POC
- "docker/Dockerfile" -- file to create Docker image
- "docker/run.sh" -- script to automate Docker image creation, run and test web-shell