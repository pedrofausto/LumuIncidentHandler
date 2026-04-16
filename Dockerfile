FROM public.ecr.aws/docker/library/python:3.12-slim

# Prevent Python from writing pyc files and keep stdout unbuffered
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create a non-root user and group
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install dependencies first (leverage Docker cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code securely
COPY src/ ./src/

# Change ownership of the application directory to the non-root user
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data
RUN chown -R appuser:appuser /app

# Drop privileges by switching to non-root user
USER appuser

# Run the orchestration script
CMD ["python", "-m", "src.main"]
