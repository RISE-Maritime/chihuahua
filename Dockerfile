FROM python:3.8-slim-bullseye

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./chihuahua /code/chihuahua

EXPOSE 80

CMD ["uvicorn", "chihuahua.main:app", "--host", "0.0.0.0", "--port", "80"]