# Use official Python lightweight image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy dependency file first (for caching)
# Note: Using requirments.txt (typo in filename) as it contains all dependencies
COPY requirments.txt requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app code
COPY . .

# TRAIN THE MODEL inside the container build
# This ensures phishing_model.pkl exists even if you didn't upload it
RUN python train.py || (echo "Training failed!" && exit 1)

# Expose API port
EXPOSE 8000

# Command to run the API
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]