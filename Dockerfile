FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
RUN useradd --create-home --uid 10001 aisx
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
USER aisx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready',timeout=2)" || exit 1
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--workers","1"]
