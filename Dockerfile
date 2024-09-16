FROM python:3.12
RUN apt update && apt install -y nmap
ADD . /code
WORKDIR /code
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "main.py"]
