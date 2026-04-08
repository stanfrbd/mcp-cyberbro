FROM python:3.13-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["mcp-cyberbro", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]