FROM python:3.11
COPY dist/n0s1-1.2.6-py3-none-any.whl /tmp/n0s1-1.2.6-py3-none-any.whl
RUN python3 -m pip install /tmp/n0s1-1.2.6-py3-none-any.whl
ENTRYPOINT ["n0s1"]