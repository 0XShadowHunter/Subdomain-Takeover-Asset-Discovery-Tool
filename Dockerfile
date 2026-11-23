# Reproducible Linux run (optional §6 deliverable).
# Build:  docker build -t subtake .
# Scan:   docker run --rm subtake scan --domain example.com --format all
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .

# The tool only detects and reports — run it against domains you own
# or are authorized to test.
ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["--help"]
