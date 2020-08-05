# ---- Base ----
FROM python:alpine AS base

#
# ---- Dependencies ----
FROM base AS dependencies
# install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt
 
#
# ---- Release ----
FROM dependencies AS release
# copy project file(s)
WORKDIR /
COPY cloudflare-ddns.py .
CMD ["python", "/cloudflare-ddns.py", "--repeat"]