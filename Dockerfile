FROM python
LABEL maintainer="@Tu5k4rr"
COPY . /CitrixHoneypot/
WORKDIR /CitrixHoneypot
RUN pip install -r requirements.txt
CMD [ "python", "./CitrixHoneypot.py" ]

