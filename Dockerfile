FROM python:3
LABEL maintainer="@Tu5k4rr"
COPY . /CitrixHoneypot/
WORKDIR /CitrixHoneypot
CMD [ "python", "./CitrixHoneypot.py"]
