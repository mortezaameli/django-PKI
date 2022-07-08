FROM python:3.8.5

# Set the timzone to Asia/Tehran
RUN ln -snf /usr/share/zoneinfo/Asia/Tehran /etc/localtime
RUN echo 'Asia/Tehran' > /etc/timezone

COPY . /apps

WORKDIR /apps

RUN apt-get update && apt-get install -y \
    libssl-dev \
    libffi-dev

RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install -r requirements.txt
RUN rm -rf /var/lib/apt/lists/*

RUN sh /apps/create_pki_db.sh

# make port 8000 available to the world outside
EXPOSE 8000

ENTRYPOINT ["sh","/apps/run_server.sh"]
