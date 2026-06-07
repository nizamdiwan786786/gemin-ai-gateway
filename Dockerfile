<<<<<<< HEAD
FROM python:3.12-slim
=======
FROM python:3.9-slim
>>>>>>> f6831a1a910403d74e66ef07b3e68433234344a1

WORKDIR /app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]