# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install basic utilities
RUN apt-get update && apt-get install -y curl wget git vim build-essential python3 python3-pip python3-venv

# Set the working directory
WORKDIR /sarr

# Copy application files (if any)
COPY . /sarr

# Set the default command
CMD ["bash"]