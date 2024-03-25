# ---- Base ----
FROM python:alpine AS base

ENV VENV_DIR="/app"
ENV PATH="${VENV_DIR}/bin:$PATH"

#
# ---- Dependencies ----
FROM base AS dependencies
# install dependencies
COPY requirements.txt /
RUN python3 -m venv "${VENV_DIR}"
RUN pip install -r /requirements.txt

#
# ---- Release ----
FROM base AS release
# copy installed dependencies and project source file(s)
WORKDIR "${VENV_DIR}"
COPY --from=dependencies "${VENV_DIR}" "${VENV_DIR}"
COPY cloudflare-ddns.py /
CMD ["python", "-u", "/cloudflare-ddns.py", "--repeat"]
