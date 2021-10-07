FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code
COPY requirements.txt /code/
RUN pip3 install -r requirements.txt \ 
	python3 manage.py migrate
 
COPY . /code/

CMD ["python3", "manage.py", "runserver"]
