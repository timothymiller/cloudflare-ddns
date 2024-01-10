# ---- Base ----
FROM python:alpine AS base
RUN adduser -D -u 1000 -g 1000 cloudflare-ddns
USER 1000:1000
WORKDIR /home/cloudflare-ddns

#
# ---- Dependencies ----
FROM base AS dependencies
# install dependencies
COPY --chown=cloudflare-ddns:cloudflare-ddns requirements.txt .
RUN pip install --user -r requirements.txt

#
# ---- Release ----
FROM base AS release
# copy installed dependencies and project source file(s)
COPY --from=dependencies /home/cloudflare-ddns/.local /home/cloudflare-ddns/.local
COPY cloudflare-ddns.py .
CMD ["python", "-u", "/home/cloudflare-ddns/cloudflare-ddns.py", "--repeat"]
