FROM python:3-alpine

RUN mkdir /app
WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY main.py .
USER nobody
CMD [ "python3", "main.py"]
