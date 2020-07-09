FROM python:3.6
WORKDIR /backend/deploy
COPY ./requirements.txt /
RUN pip install -r /requirements.txt
COPY . /backend/deploy
CMD ["python", "/backend/deploy/app.py"]
