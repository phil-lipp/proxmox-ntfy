# Proxmox Ntfy

![Preview](docs/images/screenshot.png)

This project provides a Python script that monitors Proxmox tasks and sends notifications using the Ntfy service.

## Features

- Monitors Proxmox tasks in real-time
- Sends notifications with task status and log details
- Supports Markdown formatting in notifications
- Configurable using environment variables
- Lightweight Docker image based on python:alpine
- Gunicorn for running the script as a service

## Installation

Pull the Docker image from Docker Hub:

```sh
docker pull ibacalu/proxmox-ntfy
```

## Configuration

The script can be configured using the following environment variables:
(Hint: use/copy the provided `example.env` in the `docker` folder)

- `NTFY_SERVER_URL`: Ntfy server URL and topic  (mandatory)
- `NTFY_TOKEN`: Ntfy authentication token (optional)
- `NTFY_USER`: Ntfy username (optional)
- `NTFY_PASS`: Ntfy password (optional)
- `LOG_LEVEL`: Logging level (default: "INFO")
- `PROXMOX_API_URL`: Proxmox API URL (mandatory)
- `PROXMOX_PORT`: Port under which Proxmox is reachable, probably 8006, if you're connecting via IP and 80 or 443, if Proxmox is behind a Reverse Proxy (mandatory)
- `VERIFY_SSL`: Whether proxmoxer should verify the SSL signature of the Proxmox host
- `PROXMOX_USER`: Proxmox username (mandatory)

If you want to use password authentication, set:
- `PROXMOX_PASS`: Proxmox password

If you want to use API Token authentication, set:
- `PROXMOX_TOKEN_NAME`: Token name set during creation, dont include the "root@pam"
- `PROXMOX_TOKEN_VALUE`: The secret that is displayed after creation

## Usage

Run the Docker container with the desired environment variables:

# Password authentication
```sh
docker run -d --name proxmox-ntfy 
    -e NTFY_SERVER_URL="https://ntfy.sh/your-topic" \
    -e PROXMOX_API_URL="your_proxmox_url" \
    -e PROXMOX_USER="your_username" \
    -e PROXMOX_PASS="your_password" \
ibacalu/proxmox-ntfy:latest
```

# API Token authentication
```sh
docker run -d --name proxmox-ntfy 
    -e NTFY_SERVER_URL="https://ntfy.sh/your-topic" \
    -e PROXMOX_API_URL="your_proxmox_url" \
    -e PROXMOX_USER="your_username" \
    -e PROXMOX_TOKEN_NAME="name_of_your_token" \
    -e PROXMOX_TOKEN_VALUE="secret_of_your_token" \
ibacalu/proxmox-ntfy:latest
```

Alternatively, you can use Docker Compose to start the container:

```sh
docker-compose -f docker/compose.yml up -d
```

The script will start monitoring Proxmox tasks and send notifications to the configured Ntfy server.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [GPL v3](LICENSE).
