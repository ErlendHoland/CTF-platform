# Dockerfile, Image, Container
FROM python:3.9

ADD app.py .

RUN pip3 install flask flask-sqlalchemy

CMD [ "py.exe", "./app.py" ]

