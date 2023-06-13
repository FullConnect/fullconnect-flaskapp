# Использование базового образа Python 3.8
FROM python:3.8

# Установка зависимостей
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# Копирование исходных файлов и запуск приложения
COPY . .
CMD [ "python", "app.py" ]