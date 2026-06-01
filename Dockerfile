FROM python:3.14-alpine
ARG VERSION
ENV VERSION=$VERSION

WORKDIR /usr/src/app

# iptables is needed at container runtime to apply rules
RUN apk add --no-cache iptables ip6tables

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

CMD ["python3", "main.py"]
