FROM python:3.11.3-bullseye
ENV CONFIG_FILE /app/CrowdStrikeSpotlight2HumioConfig.ini
ENV CHECKPOINT_FILE /data/checkpoint.ini
ENV LOG_FILE -
RUN mkdir /app
RUN mkdir /data

WORKDIR /app
COPY CrowdStrikeSpotlight2HumioConfig.ini CrowdStrikeSpotlight2HumioMainV2.py Send2HumioHECV2.py CrowdStrikeSpotlight2HumioErrorsV2.py LICENSE requirements.txt /app/
RUN cd /app/; pip3 install -r /app/requirements.txt; rm /app/requirements.txt

CMD ["python3","/app/CrowdStrikeSpotlight2HumioMainV2.py"]