FROM python:3.10-slim-buster

WORKDIR /app
COPY . /app/

COPY requirements.txt requirements.txt
RUN apt update \
    && apt install -y gcc python3-dev default-libmysqlclient-dev pkg-config wget unzip bzip2 firefox-esr \
    && wget https://github.com/mozilla/geckodriver/releases/download/v0.31.0/geckodriver-v0.31.0-linux64.tar.gz \
    && tar xf geckodriver-v0.31.0-linux64.tar.gz \
    && rm geckodriver-v0.31.0-linux64.tar.gz \
    && pip install -r requirements.txt \
    && python setup_database.py


# Disable buffered Python & pycache
ENV PYTHONUNBUFFERED=TRUE
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "app.py"]