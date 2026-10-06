# Generating a CodeQL Satatic Scan
Github CodeQL can generate SARIF static scans, I intend to update this codebase to allow passing an input SARIF scan and have the LLM evaluate each finding. This document is to document the process for generating the scan from CodeQL.

## Scanning Interpreted Languages
For interpreted languages (Python, JavaScript, TypeScript, etc.), CodeQL standard container can scan these directly

```
docker pull mcr.microsoft.com/cstsectools/codeql-container
docker run --rm --name codeql-db -v "C:\path\to\src:/opt/src" -v "C:\path\to\results:/opt/results" -w /opt/src --entrypoint /bin/sh codeql-custom -c "codeql database create /opt/results/source_db -s /opt/src --language=<LANGUAGE>" mcr.microsoft.com/cstsectools/codeql-container
docker run --rm --name codeql-analyze -v "C:\path\to\src:/opt/src" -v "C:\path\to\results:/opt/results" -w /opt/src --entrypoint /bin/sh codeql-custom -c "codeql database analyze /opt/results/source_db <LANGUAGE>-security-extended.qls --format=sarif-latest --output=/opt/results/issues.sarif"
```

## Scanning Compiled Languages
For compiled languages (C, C++, C#, etc), CodeQL must compile them so that it may follow along with the compilation process to analize them. You'll likely need to also construct a Docker container with the required tools to compile with.

```Dockerfile
FROM mcr.microsoft.com/cstsectools/codeql-container
USER root
RUN apt-get update && apt-get install -y libssl-dev
```

Build the Docker image from the file
```
docker build -t codeql-custom "C:\path\to\dockerfile\folder"
```

Compile the code using the Docker container
```
docker run --rm --name codeql-db -v "C:\path\to\src:/opt/src" -v "C:\path\to\results:/opt/results" -w /opt/src --entrypoint /bin/sh codeql-custom -c "codeql database create /opt/results/source_db --language=cpp --command='make clean all'"
```

Generate the final SARIF report
```
docker run --rm --name codeql-analyze -v "C:\path\to\src:/opt/src" -v "C:\path\to\results:/opt/results" -w /opt/src --entrypoint /bin/sh codeql-custom -c "codeql database analyze /opt/results/source_db cpp-security-extended.qls --format=sarif-latest --output=/opt/results/issues.sarif"
```
