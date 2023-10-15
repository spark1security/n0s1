FROM python:3.9
RUN pip install n0s1 --upgrade
ENTRYPOINT ["n0s1"]