# Multi-platform example Dockerfile for quark
FROM alpine:3.19

# Create a simple test script
RUN echo '#!/bin/bash' > /usr/local/bin/hello && \
    echo 'echo "Hello from $(uname -m) architecture!"' >> /usr/local/bin/hello && \
    chmod +x /usr/local/bin/hello

# Set working directory
WORKDIR /app

# Default command
CMD ["/usr/local/bin/hello"]
