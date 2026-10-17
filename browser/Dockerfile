FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      xvfb libgtk-3-0 libx11-xcb1 libasound2 libdbus-glib-1-2 libxt6 libpci3 fonts-dejavu-core fonts-noto-cjk ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10791 relogin
USER relogin
ENV PATH=/home/relogin/.local/bin:$PATH
RUN pip install --user --no-cache-dir "camoufox[geoip]==0.5.8" pyotp==2.9.0 && python -m camoufox fetch
WORKDIR /work
