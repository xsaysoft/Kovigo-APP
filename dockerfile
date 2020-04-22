FROM python:3

LABEL Author="Kevin"
LABEL E-mail="kevin@appmartgroup.com"

COPY . /case
WORKDIR /case
RUN pip install -r requirements.txt
CMD [ "python", "run.py" ]