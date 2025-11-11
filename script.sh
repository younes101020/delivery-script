#!/bin/bash
## Do not modify this file. You will lose the ability to install and auto-update!

set -e # Exit immediately if a command exits with a non-zero status
## $1 could be empty, so we need to disable this check
#set -u # Treat unset variables as an error and exit
set -o pipefail # Cause a pipeline to return the status of the last command that exited with a non-zero status
DATE=$(date +"%Y%m%d-%H%M%S")

VERSION="1.6"
DOCKER_VERSION="27.0.3"
CURRENT_USER=$USER
DELIVERY_SERVICES=("delivery_bull_queue" "delivery_database" "delivery_jobs" "delivery_traefik", "delivery_web")
DELIVERY_SERVICES_HEALTH_CHECK_INTERVAL=30

TOTAL_SPACE=$(df -BG / | awk 'NR==2 {print $2}' | sed 's/G//')
AVAILABLE_SPACE=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
REQUIRED_TOTAL_SPACE=30
REQUIRED_AVAILABLE_SPACE=20
WARNING_SPACE=false

set +e
DEFAULT_PRIVATE_IP=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')
PRIVATE_IPS=$(hostname -I)
set -e

if [ "$TOTAL_SPACE" -lt "$REQUIRED_TOTAL_SPACE" ]; then
    WARNING_SPACE=true
    cat << EOF
WARNING: Insufficient total disk space!

Total disk space:     ${TOTAL_SPACE}GB
Required disk space:  ${REQUIRED_TOTAL_SPACE}GB

==================
EOF
fi

if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_AVAILABLE_SPACE" ]; then
    cat << EOF
WARNING: Insufficient available disk space!

Available disk space:   ${AVAILABLE_SPACE}GB
Required available space: ${REQUIRED_AVAILABLE_SPACE}GB

==================
EOF
WARNING_SPACE=true
fi

if [ "$WARNING_SPACE" = true ]; then
    echo "Sleeping for 5 seconds."
    sleep 5
fi

mkdir -p /data/delivery/{source,ssh,applications,databases,backups,services}
mkdir -p /data/delivery/source/infrastructure/traefik-config
mkdir -p /data/delivery/ssh/{keys,mux}

chown -R 1001:root /data/delivery
chmod -R 700 /data/delivery

INSTALLATION_LOG_WITH_DATE="/data/delivery/source/installation-${DATE}.log"

exec > >(tee -a $INSTALLATION_LOG_WITH_DATE) 2>&1

OS_TYPE=$(grep -w "ID" /etc/os-release | cut -d "=" -f 2 | tr -d '"')
ENV_FILE="/data/delivery/source/.env"

# Check if the OS is manjaro, if so, change it to arch
if [ "$OS_TYPE" = "manjaro" ] || [ "$OS_TYPE" = "manjaro-arm" ]; then
    OS_TYPE="arch"
fi

# Check if the OS is Asahi Linux, if so, change it to fedora
if [ "$OS_TYPE" = "fedora-asahi-remix" ]; then
    OS_TYPE="fedora"
fi

# Check if the OS is popOS, if so, change it to ubuntu
if [ "$OS_TYPE" = "pop" ]; then
    OS_TYPE="ubuntu"
fi

# Check if the OS is linuxmint, if so, change it to ubuntu
if [ "$OS_TYPE" = "linuxmint" ]; then
    OS_TYPE="ubuntu"
fi

#Check if the OS is zorin, if so, change it to ubuntu
if [ "$OS_TYPE" = "zorin" ]; then
    OS_TYPE="ubuntu"
fi

if [ "$OS_TYPE" = "arch" ] || [ "$OS_TYPE" = "archarm" ]; then
    OS_VERSION="rolling"
else
    OS_VERSION=$(grep -w "VERSION_ID" /etc/os-release | cut -d "=" -f 2 | tr -d '"')
fi

# Install xargs on Amazon Linux 2023 - lol
if [ "$OS_TYPE" = 'amzn' ]; then
    dnf install -y findutils >/dev/null
fi

if [ $EUID != 0 ]; then
    echo "Please run as root"
    exit
fi

case "$OS_TYPE" in
arch | ubuntu | debian | raspbian | centos | fedora | rhel | ol | rocky | sles | opensuse-leap | opensuse-tumbleweed | almalinux | amzn | alpine) ;;
*)
    echo "This script only supports Debian, Redhat, Arch Linux, Alpine Linux, or SLES based operating systems for now."
    exit
    ;;
esac

# Overwrite LATEST_VERSION if user pass a version number
if [ "$1" != "" ]; then
    LATEST_VERSION=$1
    LATEST_VERSION="${LATEST_VERSION,,}"
    LATEST_VERSION="${LATEST_VERSION#v}"
fi

echo -e "\033[0;33m"
cat << "EOF"
____       _ _                     
|  _ \  ___| (_)_   _____ _ __ _   _
| | | |/ _ \ | \ \ / / _ \ '__| | | |
| |_| |  __/ | |\ V /  __/ |  | |_| |
|____/ \___|_|_| \_/ \___|_|   \__, |
                               |___/
EOF
echo -e "\033[0m"
echo -e "Welcome to Delivery Installer!"
echo -e "This script will install everything for you. Sit back and relax."
echo -e "---------------------------------------------"
echo "| Operating System  | $OS_TYPE $OS_VERSION"
echo "| Docker            | $DOCKER_VERSION"
echo -e "---------------------------------------------\n"
echo -e "1. Installing required packages (curl, wget, git, jq). "

case "$OS_TYPE" in
arch)
    pacman -Sy --noconfirm --needed curl wget git jq >/dev/null || true
    ;;
alpine)
    sed -i '/^#.*\/community/s/^#//' /etc/apk/repositories
    apk update >/dev/null
    apk add curl wget git jq >/dev/null
    ;;
ubuntu | debian | raspbian)
    apt-get update -y >/dev/null
    apt-get install -y curl wget git jq >/dev/null
    ;;
centos | fedora | rhel | ol | rocky | almalinux | amzn)
    if [ "$OS_TYPE" = "amzn" ]; then
        dnf install -y wget git jq >/dev/null
    else
        if ! command -v dnf >/dev/null; then
            yum install -y dnf >/dev/null
        fi
        if ! command -v curl >/dev/null; then
            dnf install -y curl >/dev/null
        fi
        dnf install -y wget git jq >/dev/null
    fi
    ;;
sles | opensuse-leap | opensuse-tumbleweed)
    zypper refresh >/dev/null
    zypper install -y curl wget git jq >/dev/null
    ;;
*)
    echo "This script only supports Debian, Redhat, Arch Linux, or SLES based operating systems for now."
    exit
    ;;
esac

RELEASE=$(curl --silent -m 10 --connect-timeout 5 "https://api.github.com/repos/younes101020/delivery/releases/latest")
DELIVERY_SOURCE_TAG=$(echo "$RELEASE" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')

PUBLIC_IP=$(curl -s https://api.ipify.org | tr "." "-")

echo -e "2. Check OpenSSH server configuration. "

# Detect OpenSSH server
SSH_DETECTED=false
if [ -x "$(command -v systemctl)" ]; then
    if systemctl status sshd >/dev/null 2>&1; then
        echo " - OpenSSH server is installed."
        SSH_DETECTED=true
    elif systemctl status ssh >/dev/null 2>&1; then
        echo " - OpenSSH server is installed."
        SSH_DETECTED=true
    fi
elif [ -x "$(command -v service)" ]; then
    if service sshd status >/dev/null 2>&1; then
        echo " - OpenSSH server is installed."
        SSH_DETECTED=true
    elif service ssh status >/dev/null 2>&1; then
        echo " - OpenSSH server is installed."
        SSH_DETECTED=true
    fi
fi


if [ "$SSH_DETECTED" = "false" ]; then
    echo " - OpenSSH server not detected. Installing OpenSSH server."
    case "$OS_TYPE" in
    arch)
        pacman -Sy --noconfirm openssh >/dev/null
        systemctl enable sshd >/dev/null 2>&1
        systemctl start sshd >/dev/null 2>&1
        ;;
    alpine)
        apk add openssh >/dev/null
        rc-update add sshd default >/dev/null 2>&1
        service sshd start >/dev/null 2>&1
        ;;
    ubuntu | debian | raspbian)
        apt-get update -y >/dev/null
        apt-get install -y openssh-server >/dev/null
        systemctl enable ssh >/dev/null 2>&1
        systemctl start ssh >/dev/null 2>&1
        ;;
    centos | fedora | rhel | ol | rocky | almalinux | amzn)
        if [ "$OS_TYPE" = "amzn" ]; then
            dnf install -y openssh-server >/dev/null
        else
            dnf install -y openssh-server >/dev/null
        fi
        systemctl enable sshd >/dev/null 2>&1
        systemctl start sshd >/dev/null 2>&1
        ;;
    sles | opensuse-leap | opensuse-tumbleweed)
        zypper install -y openssh >/dev/null
        systemctl enable sshd >/dev/null 2>&1
        systemctl start sshd >/dev/null 2>&1
        ;;
    *)
        echo "###############################################################################"
        echo "WARNING: Could not detect and install OpenSSH server - this does not mean that it is not installed or not running, just that we could not detect it."
        echo -e "Please make sure it is installed and running, otherwise Delivery cannot connect to the host system. \n"
        echo "###############################################################################"
        exit 1
        ;;
    esac
    echo " - OpenSSH server installed successfully."
    SSH_DETECTED=true
fi

# Detect SSH PermitRootLogin
SSH_PERMIT_ROOT_LOGIN=$(sshd -T | grep -i "permitrootlogin" | awk '{print $2}') || true
if [ "$SSH_PERMIT_ROOT_LOGIN" = "yes" ] || [ "$SSH_PERMIT_ROOT_LOGIN" = "without-password" ] || [ "$SSH_PERMIT_ROOT_LOGIN" = "prohibit-password" ]; then
    echo " - SSH PermitRootLogin is enabled."
else
    echo " - SSH PermitRootLogin is disabled."
fi

# Detect if docker is installed via snap
if [ -x "$(command -v snap)" ]; then
    SNAP_DOCKER_INSTALLED=$(snap list docker >/dev/null 2>&1 && echo "true" || echo "false")
    if [ "$SNAP_DOCKER_INSTALLED" = "true" ]; then
        echo " - Docker is installed via snap."
        echo "   Please note that Delivery does not support Docker installed via snap."
        echo "   Please remove Docker with snap (snap remove docker) and reexecute this script."
        exit 1
    fi
fi

echo -e "3. Check Docker Installation. "
if ! [ -x "$(command -v docker)" ]; then
    echo " - Docker is not installed. Installing Docker. It may take a while."
    case "$OS_TYPE" in
        "almalinux")
            dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>&1
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
            if ! [ -x "$(command -v docker)" ]; then
                echo " - Docker could not be installed automatically. Please visit https://docs.docker.com/engine/install/ and install Docker manually to continue."
                exit 1
            fi
            systemctl start docker >/dev/null 2>&1
            systemctl enable docker >/dev/null 2>&1
            ;;
        "alpine")
            apk add docker docker-cli-compose >/dev/null 2>&1
            rc-update add docker default >/dev/null 2>&1
            service docker start >/dev/null 2>&1
            if ! [ -x "$(command -v docker)" ]; then
                echo " - Failed to install Docker with apk. Try to install it manually."
                echo "   Please visit https://wiki.alpinelinux.org/wiki/Docker for more information."
                exit 1
            fi
            ;;
        "arch")
            pacman -Sy docker docker-compose --noconfirm >/dev/null 2>&1
            systemctl enable docker.service >/dev/null 2>&1
            if ! [ -x "$(command -v docker)" ]; then
                echo " - Failed to install Docker with pacman. Try to install it manually."
                echo "   Please visit https://wiki.archlinux.org/title/docker for more information."
                exit 1
            fi
            ;;
        "amzn")
            dnf install docker -y >/dev/null 2>&1
            DOCKER_CONFIG=${DOCKER_CONFIG:-/usr/local/lib/docker}
            mkdir -p $DOCKER_CONFIG/cli-plugins >/dev/null 2>&1
            curl -sL https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m) -o $DOCKER_CONFIG/cli-plugins/docker-compose >/dev/null 2>&1
            chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose >/dev/null 2>&1
            systemctl start docker >/dev/null 2>&1
            systemctl enable docker >/dev/null 2>&1
            if ! [ -x "$(command -v docker)" ]; then
                echo " - Failed to install Docker with dnf. Try to install it manually."
                echo "   Please visit https://www.cyberciti.biz/faq/how-to-install-docker-on-amazon-linux-2/ for more information."
                exit 1
            fi
            ;;
        "fedora")
            if [ -x "$(command -v dnf5)" ]; then
                # dnf5 is available
                dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo --overwrite >/dev/null 2>&1
            else
                # dnf5 is not available, use dnf
                dnf config-manager --add-repo=https://download.docker.com/linux/fedora/docker-ce.repo >/dev/null 2>&1
            fi
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
            if ! [ -x "$(command -v docker)" ]; then
                echo " - Docker could not be installed automatically. Please visit https://docs.docker.com/engine/install/ and install Docker manually to continue."
                exit 1
            fi
            systemctl start docker >/dev/null 2>&1
            systemctl enable docker >/dev/null 2>&1
            ;;
        *)
            if [ "$OS_TYPE" = "ubuntu" ] && [ "$OS_VERSION" = "24.10" ]; then
                echo "Docker automated installation is not supported on Ubuntu 24.10 (non-LTS release)."
                    echo "Please install Docker manually."
                exit 1
            fi
            curl -s https://releases.rancher.com/install-docker/${DOCKER_VERSION}.sh | sh 2>&1
            if ! [ -x "$(command -v docker)" ]; then
                curl -s https://get.docker.com | sh -s -- --version ${DOCKER_VERSION} 2>&1
                if ! [ -x "$(command -v docker)" ]; then
                    echo " - Docker installation failed."
                    echo "   Maybe your OS is not supported?"
                    echo " - Please visit https://docs.docker.com/engine/install/ and install Docker manually to continue."
                    exit 1
                fi
            fi
    esac
    echo " - Docker installed successfully."
else
    echo " - Docker is installed."
fi

echo -e "5. Download required files from CDN. "
curl -fsSL http://deliveryinstallresources.younesfakallah.com/compose.prod.yaml -o /data/delivery/source/compose.prod.yaml
#curl -fsSL https://raw.githubusercontent.com/younes101020/delivery/refs/heads/main/infrastructure/traefik-config/acme.json -o /data/delivery/source/infrastructure/traefik-config/acme.json || true
curl -fsSL http://deliveryinstallresources.younesfakallah.com/dynamic.yaml -o /data/delivery/source/infrastructure/traefik-config/dynamic.yaml
curl -fsSL http://deliveryinstallresources.younesfakallah.com/traefik.yaml -o /data/delivery/source/infrastructure/traefik-config/traefik.yaml
curl -fsSL http://deliveryinstallresources.younesfakallah.com/env.production -o /data/delivery/source/.env.production

#chmod 600 /data/delivery/source/infrastructure/traefik-config/acme.json || true

echo -e "6. Make backup of .env to .env-$DATE"

# Copy .env.example if .env does not exist
if [ -f $ENV_FILE ]; then
    cp $ENV_FILE $ENV_FILE-$DATE
else
    echo " - File does not exist: $ENV_FILE"
    echo " - Copying .env.production to .env"
    cp /data/delivery/source/.env.production $ENV_FILE

    # Generate a secure Postgres DB password
    DB_PASSWORD=$(openssl rand -base64 12 | tr -dc "A-Za-z0-9")
    
    sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$DB_PASSWORD|" "$ENV_FILE"
    sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgres://productiondb:$DB_PASSWORD@tasks.delivery_database:5432/productiondb|" "$ENV_FILE"

    # Set the default host for ssh
    sed -i "s|^SSH_HOST=.*|SSH_HOST=$DEFAULT_PRIVATE_IP|" "$ENV_FILE"

    # Set the host public ip
    sed -i "s|^PUBLIC_IP=.*|PUBLIC_IP=$PUBLIC_IP|" "$ENV_FILE"

    # Generate bearer token for rest API
    BEARER_TOKEN=$(openssl rand -hex 16)

    sed -i "s|^BEARER_TOKEN=.*|BEARER_TOKEN=$BEARER_TOKEN|" "$ENV_FILE"
    sed -i "s|^JOBS_BEARER_TOKEN=.*|JOBS_BEARER_TOKEN=$BEARER_TOKEN|" "$ENV_FILE"

    # Set the public url of web service
    sed -i "s|^WEB_BASE_URL=.*|WEB_BASE_URL=https://$PUBLIC_IP.sslip.io|" "$ENV_FILE"

    # Generate a secure authentication token (will be used to generate a JWT token)
    AUTH_SECRET=$(openssl rand -hex 32)

    sed -i "s|^AUTH_SECRET=.*|AUTH_SECRET=$AUTH_SECRET|" "$ENV_FILE"

    # Set the latest docker tag of delivery source
    DOCKER_TAGS=$DELIVERY_SOURCE_TAG-latest

    sed -i "s|^DOCKER_TAGS=.*|DOCKER_TAGS=$DOCKER_TAGS|" "$ENV_FILE"

    # Generate a secure Redis password
    REDIS_PASSWORD=$(openssl rand -base64 12 | tr -dc "A-Za-z0-9")
    
    sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$REDIS_PASSWORD|" "$ENV_FILE"

    # Set the docker group id env var
    DOCKER_GID=$(grep "^docker:" /etc/group | cut -d: -f3)

    sed -i "s|^DOCKER_GID=.*|DOCKER_GID=$DOCKER_GID|" "$ENV_FILE"
fi

echo -e "8. Checking for SSH key for localhost access."
if [ ! -f ~/.ssh/authorized_keys ]; then
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    touch ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
fi

set +e
IS_DELIVERY_VOLUME_EXISTS=$(docker volume ls | grep delivery-db | wc -l)
set -e

if [ "$IS_DELIVERY_VOLUME_EXISTS" -eq 0 ]; then
    echo " - Generating SSH key."
    ssh-keygen -t ed25519 -a 100 -f /data/delivery/ssh/keys/id.$CURRENT_USER@host.docker.internal -q -N "" -C delivery
    chown 1001 /data/delivery/ssh/keys/id.$CURRENT_USER@host.docker.internal
    sed -i "/delivery/d" ~/.ssh/authorized_keys
    cat /data/delivery/ssh/keys/id.$CURRENT_USER@host.docker.internal.pub >> ~/.ssh/authorized_keys
    rm -f /data/delivery/ssh/keys/id.$CURRENT_USER@host.docker.internal.pub
fi

chown -R 1001:root /data/delivery
chmod -R 700 /data/delivery

echo -e "9. Installing image builder."

curl -sSL https://nixpacks.com/install.sh | bash >/dev/null 2>&1

echo -e "10. Enabling Docker Swarm mode."

docker swarm init >/dev/null 2>&1

echo -e "11. Starting delivery service."

docker network create --driver overlay --attachable proxy
env $(grep -v '^#' /data/delivery/source/.env | xargs) docker stack deploy -c /data/delivery/source/compose.prod.yaml delivery

while true; do
    all_up=true
    
    for SERVICE in "${DELIVERY_SERVICES[@]}"; do
        if ! docker service ps "$SERVICE" --filter "desired-state=running" | grep -q "Running"; then
            all_up=false
        fi
    done
    
    if [ "$all_up" = true ]; then
        break
    fi
    
    sleep "$DELIVERY_SERVICES_HEALTH_CHECK_INTERVAL"
done

echo -e "\033[0;33m
   ____                            _         _       _   _                 _
  / ___|___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_(_) ___  _ __  ___| |
 | |   / _ \| '_ \ / _\` | '__/ _\` | __| | | | |/ _\` | __| |/ _ \| '_ \/ __| |
 | |__| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | \__ \_|
  \____\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|___(_)
                   |___/
\033[0m"

echo -e "\033[0;34mgo to https://$PUBLIC_IP.sslip.io\033[0m"
