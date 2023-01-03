FROM python:latest

ENV SRC="."

VOLUME /bind-adblock

COPY ${SRC}/blocklist.txt ./
COPY ${SRC}/config.yml ./
COPY ${SRC}/update-zonefile.py ./
COPY ${SRC}/requirements.txt ./

RUN pip install -r requirements.txt

CMD ["python3", "./update-zonefile.py", "--no-bind", "/bind-adblock/rpz-adblocker.zone", "rpz.adblocker"]
