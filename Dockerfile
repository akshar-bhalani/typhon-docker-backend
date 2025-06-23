FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .



COPY . .

ENV VIRTUAL_ENV="/app/venv"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN python3 -m venv /app/venv


# Upgrade pip and install dependencies
RUN /app/venv/bin/python -m ensurepip --upgrade
RUN /app/venv/bin/pip install --no-cache-dir --upgrade pip
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt



EXPOSE 8000

CMD ["/bin/bash", "-c", "/app/venv/bin/python manage.py migrate && /app/venv/bin/python manage.py runserver 0.0.0.0:8000"]




