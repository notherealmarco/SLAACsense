FROM python:latest
LABEL authors="notherealmarco"
WORKDIR /app/
COPY . .
RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "/app/main.py"]