FROM python
LABEL maintainer="Bontchev"
LABEL name="CitrixHoneypot"
LABEL version="2.0.3"
EXPOSE 443
COPY . /CitrixHoneypot/
WORKDIR /CitrixHoneypot
RUN pip install -r requirements.txt
CMD [ "python", "./CitrixHoneypot.py" ]

