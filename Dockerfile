# ---- Base ----
FROM python:alpine AS base

#
# ---- Dependencies ----
FROM base AS dependencies
# install dependencies
COPY requirements.txt .
RUN pip install --user -r requirements.txt

#
# ---- Release ----
FROM base AS release
# copy installed dependencies and project source file(s)
WORKDIR /
COPY --from=dependencies /root/.local /root/.local
COPY cloudflare-ddns.py .
CMD ["python", "-u", "/cloudflare-ddns.py", "--repeat"]
