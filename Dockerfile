FROM balenalib/armv7hf-debian-python:3.9-sid-build

# This Dockerfile is used to build an image for the BalenaCloud service
# This is probably not working on your normal system

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "app.py" ]